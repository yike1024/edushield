// Run: tsx src/__tests__/web-projects.test.ts
//
// 17 号方案 · 方案 B：浏览器模式评估项目存储（src/lib/webProjects.ts）回归测试。
// 覆盖：
//   1) project:// root 工具函数（含 local→server 别名解析）；
//   2) sortProjects（置顶 → order → updatedAt）；
//   3) local 降级模式 CRUD / 激活 / 排序 / LS 持久化；
//   4) 后端 404（尚未部署 projects）时静默 local 降级、数据不丢；
//   5) 后端上线后的一次性 local→server 迁移与别名。

// 最小 localStorage polyfill：必须在 import webProjects 之前安装
class MemLocalStorage {
  private map = new Map<string, string>();
  getItem(key: string): string | null { return this.map.has(key) ? this.map.get(key)! : null; }
  setItem(key: string, value: string): void { this.map.set(key, String(value)); }
  removeItem(key: string): void { this.map.delete(key); }
  clear(): void { this.map.clear(); }
}
(globalThis as unknown as { localStorage: MemLocalStorage }).localStorage = new MemLocalStorage();

import {
  webProjects,
  projectRoot,
  isProjectRoot,
  projectIdFromRoot,
  sortProjects,
  PROJECT_ROOT_PREFIX,
  type WebProject,
} from "../lib/webProjects";
import { aisocApi } from "../lib/aisoc-api";

let passed = 0;
let failed = 0;
function ok(cond: boolean, label: string) {
  if (cond) { passed++; console.log(`  ✅ ${label}`); }
  else { failed++; console.error(`  ❌ ${label}`); }
}

// 18 号方案：用户域键带命名空间后缀；测试环境未登录 → ':anon'
const LS_PROJECTS = "reasonix:web:projects:v1:anon";
const LS_MIGRATED = "reasonix:web:projects:migrated:anon";
const LS_ALIASES = "reasonix:web:projects:aliases:anon";
const LS_ACTIVE = "reasonix:web:projects:active:anon";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function iso(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

async function main() {
  // ========== 1) root 工具函数 ==========
  console.log("root 工具函数:");
  ok(projectRoot("abc") === `${PROJECT_ROOT_PREFIX}abc`, "projectRoot 拼接 project:// 前缀");
  ok(isProjectRoot("project://local-1") === true, "isProjectRoot 识别项目 root");
  ok(isProjectRoot("/home/user/proj") === false && isProjectRoot(null) === false && isProjectRoot(undefined) === false,
    "isProjectRoot 拒绝普通路径/空值");
  ok(projectIdFromRoot("project://local-xyz") === "local-xyz", "projectIdFromRoot 提取未知 id 原样返回");
  ok(projectIdFromRoot("/etc") === null, "projectIdFromRoot 对非项目 root 返回 null");

  // ========== 2) sortProjects ==========
  console.log("sortProjects 排序规则:");
  const unsorted: WebProject[] = [
    { id: "c", name: "C", pinned: false, order: 2, createdAt: iso(1), updatedAt: iso(10) },
    { id: "a", name: "A", pinned: false, order: 0, createdAt: iso(1), updatedAt: iso(20) },
    { id: "p", name: "P", pinned: true, order: 99, createdAt: iso(1), updatedAt: iso(5) },
    { id: "b", name: "B", pinned: false, order: 0, createdAt: iso(1), updatedAt: iso(30) },
    { id: "d", name: "D", pinned: false, order: undefined, createdAt: iso(1), updatedAt: iso(40) },
  ];
  const sorted = sortProjects(unsorted).map((p) => p.id);
  ok(sorted[0] === "p", "置顶项目排最前");
  ok(sorted.slice(1, 3).join(",") === "b,a", "同 order 按 updatedAt 降序");
  ok(sorted[3] === "c" && sorted[4] === "d", "order 升序，无 order 垫底");
  ok(unsorted[0].id === "c", "sortProjects 不改原数组");

  // ========== 3) local 降级 CRUD（无 token） ==========
  console.log("local 模式 CRUD + 持久化:");
  ok(!aisocApi.hasAuthToken(), "初始无 token（local 模式前提）");
  let threw = false;
  try { await webProjects.create({ name: "   " }); } catch { threw = true; }
  ok(threw, "空名称拒绝创建");

  const p1 = await webProjects.create({ name: "  某中学官网评估 ", target: " 10.20.1.0/24 ", color: "blue" });
  ok(p1.id.startsWith("local-") && p1.local === true, "local 项目 id 带 local- 前缀并打 local 标记");
  ok(p1.name === "某中学官网评估" && p1.target === "10.20.1.0/24", "名称/目标自动 trim");
  const p2 = await webProjects.create({ name: "政务网段巡检", target: "10.30.0.0/16" });

  const persisted = JSON.parse(localStorage.getItem(LS_PROJECTS) || "[]") as WebProject[];
  ok(persisted.some((p) => p.id === p1.id && p.target === "10.20.1.0/24"), "创建后写入 LS 快照");

  ok(webProjects.getById(p1.id)?.id === p1.id, "getById 命中");
  ok(webProjects.getByRoot(projectRoot(p1.id))?.id === p1.id, "getByRoot 按 project:// root 命中");
  ok(webProjects.getByRoot("/") === undefined, "getByRoot 普通路径返回 undefined");

  webProjects.setActive(p1.id);
  ok(webProjects.getActiveId() === p1.id && localStorage.getItem(LS_ACTIVE) === JSON.stringify(p1.id),
    "setActive 生效并持久化");

  await webProjects.update(p1.id, { pinned: true, name: "  改名后  " });
  ok(webProjects.getById(p1.id)?.pinned === true && webProjects.getById(p1.id)?.name === "改名后",
    "update 改置顶/名称生效");
  ok(webProjects.getAll()[0].id === p1.id, "置顶项目排到列表首位");

  await webProjects.reorder([p2.id, p1.id]);
  const p2Order = webProjects.getById(p2.id)?.order;
  const p1Order = webProjects.getById(p1.id)?.order;
  ok(typeof p2Order === "number" && typeof p1Order === "number" && (p2Order as number) < (p1Order as number),
    "reorder 按给定 id 顺序写 order");

  await webProjects.remove(p1.id);
  ok(webProjects.getById(p1.id) === undefined, "remove 删除项目");
  ok(webProjects.getActiveId() === null, "删除激活项目后激活清空");

  // ========== 4) 后端 404 → 静默降级 ==========
  console.log("服务端 404（未部署 projects）降级:");
  aisocApi.setAuthToken("test-token-17");
  (globalThis as { fetch: unknown }).fetch = async () => jsonResponse({ detail: "Not Found" }, 404);
  const after404 = await webProjects.ensureLoaded(true);
  ok(!webProjects.isServerMode(), "404 后 isServerMode=false");
  ok(after404.some((p) => p.id === p2.id), "404 时本地项目不丢失");

  // ========== 5) 后端上线 → 一次性迁移 + 别名 ==========
  console.log("local→server 一次性迁移:");
  localStorage.removeItem(LS_MIGRATED);
  const serverId = "11111111-2222-3333-4444-555555555555";
  let getCalls = 0;
  // 用对象包裹捕获 POST 体：fetch mock 里的赋值不会被 TS 控制流分析看见，
  // 直接判断 `let postBody = null` 会被收窄成 never。
  const captured: { post?: Record<string, unknown> } = {};
  (globalThis as { fetch: unknown }).fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method || "GET").toUpperCase();
    if (url.includes("/projects") && method === "GET") {
      getCalls += 1;
      // 第一次拉取：服务端为空（触发迁移）；第二次：迁移后回拉包含新建项目
      if (getCalls === 1) return jsonResponse({ items: [], total: 0, page: 1, pageSize: 200 });
      return jsonResponse({
        items: [{
          id: serverId, name: "政务网段巡检", target: "10.30.0.0/16",
          description: null, color: null, pinned: false, order: 0, status: "active",
          createdAt: iso(100), updatedAt: iso(100),
          conversationCount: 0, taskCount: 0, findingCount: 0,
        }],
        total: 1, page: 1, pageSize: 200,
      });
    }
    if (url.includes("/projects") && method === "POST") {
      const postBody = JSON.parse(String(init?.body || "{}")) as Record<string, unknown>;
      captured.post = postBody;
      return jsonResponse({
        id: serverId, name: postBody.name, target: postBody.target ?? null,
        description: postBody.description ?? null, color: postBody.color ?? null,
        pinned: false, order: 0, status: "active",
        createdAt: iso(100), updatedAt: iso(100),
      });
    }
    return jsonResponse({ detail: "unexpected request" }, 500);
  };

  const migrated = await webProjects.ensureLoaded(true);
  ok(webProjects.isServerMode(), "200 后 isServerMode=true");
  ok(captured.post?.name === "政务网段巡检" && captured.post?.target === "10.30.0.0/16",
    "迁移 POST 携带本地项目字段");
  ok(migrated.some((p) => p.id === serverId), "迁移后列表为服务端项目");
  const aliases = JSON.parse(localStorage.getItem(LS_ALIASES) || "{}") as Record<string, string>;
  ok(aliases[p2.id] === serverId, "localId→serverId 别名持久化");
  ok(localStorage.getItem(LS_MIGRATED) === "true", "迁移标记只跑一次");
  ok(projectIdFromRoot(projectRoot(p2.id)) === serverId, "旧 tab 的 project://local-... root 经别名解析到 serverId");
  ok(webProjects.getByRoot(projectRoot(p2.id))?.id === serverId, "getByRoot 经别名找到服务端项目");

  // 再 force 拉取一次不应再迁移
  const callCountBefore = getCalls;
  await webProjects.ensureLoaded(true);
  ok(getCalls === callCountBefore + 1, "已迁移后再次加载只 GET 不 POST");

  console.log(`\n结果: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(2); });
