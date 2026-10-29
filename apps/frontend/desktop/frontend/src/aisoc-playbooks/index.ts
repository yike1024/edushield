/**
 * 静态预案（Playbook）库
 *
 * 设计：每个 .md 模板有 YAML frontmatter（id / name / threat_class / rule_ids /
 * severity / tags / estimated_minutes / updated），后面是 markdown 正文。
 *
 * 匹配规则（前端）：
 *   - 告警的 threat_class 命中 playbook.threat_class（数字 / 数组）
 *   - 告警的 rule_id 命中 playbook.rule_ids
 *   - threat_class 越具体优先级越高（> rule_id 通用匹配）
 *
 * 注意：当前为前端静态方案（aisoc-playbooks/*.md），后端无 /api/playbooks
 * 端点（incident 部件二期未实现）。若后端实现后，本模块可平滑切换。
 */

import credRaw from './PB-001-credential-leak.md?raw';
import webRaw from './PB-002-web-attack.md?raw';
import ddosRaw from './PB-003-ddos.md?raw';

export interface PlaybookMeta {
  id: string;
  name: string;
  /** 匹配的威胁大类编号。单个数字或数组。 */
  threat_class?: number | number[];
  /** 匹配的 XDR 规则 ID 列表 */
  rule_ids?: string[];
  /** 严重度级别：critical / high / medium / low / info */
  severity?: string;
  /** 标签（用于搜索） */
  tags?: string[];
  /** 预计处置时长（分钟） */
  estimated_minutes?: number;
  /** 最后更新日期 (YYYY-MM-DD) */
  updated?: string;
}

export interface Playbook {
  meta: PlaybookMeta;
  /** Markdown 正文（不含 frontmatter） */
  body: string;
}

/** 极简 YAML frontmatter 解析（只支持本项目预案的字段） */
function parsePlaybook(raw: string): Playbook {
  const m = raw.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (!m) {
    return { meta: { id: 'unknown', name: '未命名' }, body: raw };
  }
  const fmLines = m[1].split('\n');
  const meta: Record<string, unknown> = {};
  for (const line of fmLines) {
    const kv = line.match(/^([\w_]+):\s*(.*)$/);
    if (!kv) continue;
    const key = kv[1];
    let val: unknown = kv[2].trim();
    if (typeof val === 'string') {
      const s = val as string;
      // 数组 [a, b, c]
      if (s.startsWith('[') && s.endsWith(']')) {
        const inner = s.slice(1, -1).trim();
        if (inner === '') {
          val = [];
        } else {
          val = inner.split(',').map((x) => {
            const t = x.trim();
            if (t.startsWith('"') || t.startsWith("'")) return t.slice(1, -1);
            if (t === 'true') return true;
            if (t === 'false') return false;
            if (/^-?\d+(\.\d+)?$/.test(t)) return Number(t);
            return t;
          });
        }
      }
      // 字符串 "..." 或 '...'
      else if (s.startsWith('"') && s.endsWith('"')) val = s.slice(1, -1);
      else if (s.startsWith("'") && s.endsWith("'")) val = s.slice(1, -1);
      // 数字
      else if (/^-?\d+(\.\d+)?$/.test(s)) val = Number(s);
      // 布尔
      else if (s === 'true') val = true;
      else if (s === 'false') val = false;
    }
    meta[key] = val;
  }
  return { meta: meta as unknown as PlaybookMeta, body: m[2] };
}

/** 全部预案（按 id 排序） */
export const PLAYBOOKS: Playbook[] = [
  parsePlaybook(credRaw),
  parsePlaybook(webRaw),
  parsePlaybook(ddosRaw),
].sort((a, b) => a.meta.id.localeCompare(b.meta.id));

/**
 * 根据告警匹配预案
 * @returns 命中的预案列表（按匹配强度排序：threat_class 命中 > rule_id 命中）
 */
export function matchPlaybooks(alarm: {
  threat_class?: number;
  rule_id?: string;
}): Playbook[] {
  const { threat_class, rule_id } = alarm;
  const out: Array<{ pb: Playbook; score: number }> = [];
  for (const pb of PLAYBOOKS) {
    let score = 0;
    if (typeof threat_class === 'number' && pb.meta.threat_class !== undefined) {
      const tcs = Array.isArray(pb.meta.threat_class) ? pb.meta.threat_class : [pb.meta.threat_class];
      if (tcs.includes(threat_class)) score += 10;
    }
    if (rule_id && pb.meta.rule_ids?.includes(String(rule_id))) score += 5;
    if (score > 0) out.push({ pb, score });
  }
  return out.sort((a, b) => b.score - a.score).map((x) => x.pb);
}

/** 按 id 查预案 */
export function getPlaybookById(id: string): Playbook | undefined {
  return PLAYBOOKS.find((p) => p.meta.id === id);
}
