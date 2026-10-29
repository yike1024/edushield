/**
 * webProjects — 浏览器模式「评估项目」存储（17 号方案 · 方案 B）
 *
 * 领域语义：一个项目 = 一次安全评估对象（如"某中学官网 10.20.1.0/24"），
 * 会话 / 任务 / 发现都挂在项目下。
 *
 * 数据源策略（与记忆功能一致：服务端可用 → 服务端权威；不可用 → localStorage 静默降级）：
 *   1. 已登录且 GET /api/projects 正常 → server 模式，CRUD 全走后端，LS 仅存快照；
 *   2. 端点 404/405（后端尚未部署该版）或网络失败/未登录 → local 模式，CRUD 走 LS；
 *   3. 后端在用户使用过 local 模式后才上线：首次拉到服务端列表时把本地项目一次性
 *      补建到服务端（迁移只跑一次），并保留 localId → serverId 别名，旧 tab 的
 *      project://local-... root 仍能解析。
 *
 * 左栏 ProjectTree 与 webApiProxy 通过 project://<id> 虚拟 workspaceRoot 引用项目。
 */

import {
  aisocApi,
  type ProjectDto,
  type ProjectCreateInput,
  type ProjectPatchInput,
  type ProjectStatus,
} from './aisoc-api';
import { readNs, writeNs } from './userScopedStorage';

/** 虚拟工作区根前缀（tab.workspaceRoot 使用） */
export const PROJECT_ROOT_PREFIX = 'project://';

export function projectRoot(id: string): string {
  return `${PROJECT_ROOT_PREFIX}${id}`;
}

export function isProjectRoot(root: string | undefined | null): boolean {
  return !!root && root.startsWith(PROJECT_ROOT_PREFIX);
}

/** 从 root 解析项目 id；自动解析 local→server 迁移别名；非项目 root 返回 null */
export function projectIdFromRoot(root: string | undefined | null): string | null {
  if (!isProjectRoot(root)) return null;
  const raw = root!.slice(PROJECT_ROOT_PREFIX.length);
  return webProjects.resolveId(raw) ?? raw;
}

export interface WebProject {
  id: string;
  name: string;
  target?: string;
  description?: string;
  color?: string;
  pinned?: boolean;
  order?: number | null;
  status?: ProjectStatus;
  createdAt: string;
  updatedAt: string;
  /** local 模式下创建的临时项目（迁移后经 aliases 指向服务端 id） */
  local?: boolean;
  // 后端聚合计数（有则显示徽标）
  conversationCount?: number;
  taskCount?: number;
  findingCount?: number;
}

export type WebProjectCreateInput = ProjectCreateInput;
export type WebProjectPatchInput = ProjectPatchInput;

// 18 号方案：用户域 base 键名，实际读写经 userScopedStorage 加 `:{userId|anon}` 后缀。
// migrated 标记随之变为 per-user——各账号的 local 项目分别迁移到各自服务端空间，语义正确。
const LS_KEY_PROJECTS = 'reasonix:web:projects:v1';
const LS_KEY_ACTIVE = 'reasonix:web:projects:active';
const LS_KEY_MIGRATED = 'reasonix:web:projects:migrated';
const LS_KEY_ALIASES = 'reasonix:web:projects:aliases';

function nowIso(): string {
  return new Date().toISOString();
}

function localId(): string {
  const rand = typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  return `local-${rand}`;
}

function readLSJson<T>(key: string, fallback: T): T {
  return readNs(key, fallback);
}

function writeLSJson(key: string, value: unknown): void {
  writeNs(key, value);
}

function fromDto(dto: ProjectDto): WebProject {
  return {
    id: dto.id,
    name: dto.name,
    target: dto.target ?? undefined,
    description: dto.description ?? undefined,
    color: dto.color ?? undefined,
    pinned: dto.pinned ?? false,
    order: dto.order ?? null,
    status: dto.status ?? 'active',
    createdAt: dto.createdAt ?? nowIso(),
    updatedAt: dto.updatedAt ?? dto.createdAt ?? nowIso(),
    conversationCount: dto.conversationCount,
    taskCount: dto.taskCount,
    findingCount: dto.findingCount,
  };
}

/** 排序：置顶优先 → order 升序 → updatedAt 降序 */
export function sortProjects(list: WebProject[]): WebProject[] {
  return [...list].sort((a, b) => {
    if (Boolean(a.pinned) !== Boolean(b.pinned)) return a.pinned ? -1 : 1;
    const ao = typeof a.order === 'number' ? a.order : Number.POSITIVE_INFINITY;
    const bo = typeof b.order === 'number' ? b.order : Number.POSITIVE_INFINITY;
    if (ao !== bo) return ao - bo;
    return String(b.updatedAt).localeCompare(String(a.updatedAt));
  });
}

class WebProjectStore {
  private projects: WebProject[] = [];
  private loaded = false;
  /** null=未知；true=服务端可用；false=local 降级 */
  private serverOnline: boolean | null = null;
  private activeId: string | null = null;
  private aliases: Record<string, string> = {};
  private listeners: Set<() => void> = new Set();

  constructor() {
    this.projects = readLSJson<WebProject[]>(LS_KEY_PROJECTS, []);
    this.activeId = readLSJson<string | null>(LS_KEY_ACTIVE, null);
    this.aliases = readLSJson<Record<string, string>>(LS_KEY_ALIASES, {});
  }

  subscribe(cb: () => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  private emit(): void {
    this.listeners.forEach((cb) => cb());
  }

  isServerMode(): boolean {
    return this.serverOnline === true;
  }

  /** localId → serverId 迁移别名解析；非别名原样返回 */
  resolveId(id: string): string | null {
    return this.aliases[id] ?? null;
  }

  private snapshot(): void {
    writeLSJson(LS_KEY_PROJECTS, this.projects);
  }

  /**
   * 加载项目列表（带缓存）。force=true 用于 CRUD 后刷新。
   * 永不抛错——后端不可达时静默返回本地数据。
   */
  async ensureLoaded(force = false): Promise<WebProject[]> {
    if (this.loaded && !force) return sortProjects(this.projects);
    if (!aisocApi.hasAuthToken()) {
      this.serverOnline = false;
      this.loaded = true;
      return sortProjects(this.projects);
    }
    try {
      const res = await aisocApi.listProjects({ pageSize: 200, status: 'active' });
      this.serverOnline = true;
      const serverItems = (res.items ?? []).map(fromDto);
      await this.migrateLocalOnce(serverItems);
      // 迁移可能补建了项目，以服务端最新结果为准再拉一次（仅迁移发生时）
      const finalItems = this.pendingMigration
        ? (await aisocApi.listProjects({ pageSize: 200, status: 'active' })).items.map(fromDto)
        : serverItems;
      this.pendingMigration = false;
      this.projects = finalItems;
      this.loaded = true;
      this.snapshot();
      this.emit();
      return sortProjects(this.projects);
    } catch (e) {
      // 404/405=后端尚未部署 projects；401=未登录；其它=网络/服务异常 → 一律 local 降级
      const status = (e as { status?: number })?.status;
      if (status && status !== 404 && status !== 405 && status !== 401) {
        console.warn('[webProjects] list failed, fallback to local:', e);
      }
      this.serverOnline = false;
      this.loaded = true;
      return sortProjects(this.projects);
    }
  }

  private pendingMigration = false;

  /** local→server 一次性迁移（每个浏览器仅跑一次） */
  private async migrateLocalOnce(serverItems: WebProject[]): Promise<void> {
    if (readLSJson<boolean>(LS_KEY_MIGRATED, false)) return;
    const locals = this.projects.filter((p) => p.local);
    writeLSJson(LS_KEY_MIGRATED, true); // 即使没有本地项目也标记完成
    if (locals.length === 0 || serverItems.length > 0) return;
    this.pendingMigration = true;
    for (const p of locals) {
      try {
        const created = await aisocApi.createProject({
          name: p.name,
          target: p.target,
          description: p.description,
          color: p.color || undefined,
        });
        this.aliases[p.id] = created.id;
      } catch (e) {
        console.warn('[webProjects] migrate project failed:', p.name, e);
      }
    }
    writeLSJson(LS_KEY_ALIASES, this.aliases);
    if (this.activeId && this.aliases[this.activeId]) {
      this.activeId = this.aliases[this.activeId];
      writeLSJson(LS_KEY_ACTIVE, this.activeId);
    }
  }

  getAll(): WebProject[] {
    return sortProjects(this.projects);
  }

  getById(id: string): WebProject | undefined {
    const canonical = this.resolveId(id) ?? id;
    return this.projects.find((p) => p.id === canonical || p.id === id);
  }

  getByRoot(root: string | undefined | null): WebProject | undefined {
    const id = projectIdFromRoot(root);
    return id ? this.getById(id) : undefined;
  }

  getActiveId(): string | null {
    return this.activeId ? (this.resolveId(this.activeId) ?? this.activeId) : null;
  }

  setActive(id: string | null): void {
    this.activeId = id ? (this.resolveId(id) ?? id) : null;
    writeLSJson(LS_KEY_ACTIVE, this.activeId);
    this.emit();
  }

  async create(input: WebProjectCreateInput): Promise<WebProject> {
    const name = input.name.trim();
    if (!name) throw new Error('项目名称不能为空');
    await this.ensureLoaded();
    if (this.serverOnline === true) {
      const dto = await aisocApi.createProject({
        name,
        target: input.target?.trim() || undefined,
        description: input.description?.trim() || undefined,
        color: input.color || undefined,
      });
      const proj = fromDto(dto);
      await this.ensureLoaded(true);
      return this.getById(proj.id) ?? proj;
    }
    const proj: WebProject = {
      id: localId(),
      name,
      target: input.target?.trim() || undefined,
      description: input.description?.trim() || undefined,
      color: input.color || undefined,
      pinned: false,
      order: this.projects.length,
      status: 'active',
      createdAt: nowIso(),
      updatedAt: nowIso(),
      local: true,
    };
    this.projects.push(proj);
    this.snapshot();
    this.emit();
    return proj;
  }

  async update(id: string, patch: WebProjectPatchInput): Promise<WebProject> {
    const canonical = this.resolveId(id) ?? id;
    await this.ensureLoaded();
    if (this.serverOnline === true) {
      await aisocApi.updateProject(canonical, patch);
      await this.ensureLoaded(true);
      const updated = this.getById(canonical);
      if (updated) return updated;
    }
    const idx = this.projects.findIndex((p) => p.id === canonical);
    if (idx < 0) throw new Error('项目不存在');
    const prev = this.projects[idx];
    const next: WebProject = {
      ...prev,
      ...(patch.name !== undefined ? { name: patch.name.trim() || prev.name } : {}),
      ...(patch.target !== undefined ? { target: patch.target ?? undefined } : {}),
      ...(patch.description !== undefined ? { description: patch.description ?? undefined } : {}),
      ...(patch.color !== undefined ? { color: patch.color ?? undefined } : {}),
      ...(patch.pinned !== undefined ? { pinned: patch.pinned } : {}),
      ...(patch.order !== undefined ? { order: patch.order } : {}),
      ...(patch.status !== undefined ? { status: patch.status } : {}),
      updatedAt: nowIso(),
    };
    this.projects[idx] = next;
    this.snapshot();
    this.emit();
    return next;
  }

  /** 删除（本地模式直接删；服务端模式调 DELETE，关联会话由后端解绑不级联） */
  async remove(id: string): Promise<void> {
    const canonical = this.resolveId(id) ?? id;
    await this.ensureLoaded();
    if (this.serverOnline === true) {
      await aisocApi.deleteProject(canonical);
      await this.ensureLoaded(true);
      return;
    }
    this.projects = this.projects.filter((p) => p.id !== canonical);
    if (this.activeId === canonical) this.setActive(null);
    this.snapshot();
    this.emit();
  }

  /** 按给定 id 顺序持久化手动排序（其它项追加在后） */
  async reorder(orderedIds: string[]): Promise<void> {
    await this.ensureLoaded();
    const rank = new Map(orderedIds.map((id, i) => [this.resolveId(id) ?? id, i]));
    const updates: Array<{ id: string; order: number }> = [];
    sortProjects(this.projects).forEach((p, i) => {
      const nextOrder = rank.get(p.id) ?? orderedIds.length + i;
      if (p.order !== nextOrder) updates.push({ id: p.id, order: nextOrder });
    });
    if (updates.length === 0) return;
    if (this.serverOnline === true) {
      await Promise.all(updates.map((u) => aisocApi.updateProject(u.id, { order: u.order }).catch(() => {})));
      await this.ensureLoaded(true);
      return;
    }
    updates.forEach((u) => {
      const p = this.projects.find((x) => x.id === u.id);
      if (p) p.order = u.order;
    });
    this.snapshot();
    this.emit();
  }
}

export const webProjects = new WebProjectStore();
