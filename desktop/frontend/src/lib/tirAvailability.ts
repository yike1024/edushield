/**
 * TIR 查询端点可用性判定。
 *
 * 背景：TIR 三端点（alerts / playbooks / reports）都做了 `.catch(() => [])` 降级，
 * 后端路由未部署（404）与“任务确实没有应急响应数据”在 UI 上都表现为空列表，
 * 演示时会被误读成“判定为非真实威胁”。这里根据三个调用的失败状态码做区分：
 *   - 全部 404            → 路由未部署（/api/tir/* 缺失）
 *   - 全部 0（网络/不可达）→ TIR 服务不可达
 *   - 任意成功 / 401 等    → 不做额外提示（401 交给全局登出处理）
 */
export type TirAvailability = 'route-missing' | 'unreachable' | null;

export function summarizeTirAvailability(
  statuses: ReadonlyArray<number | null>,
): TirAvailability {
  if (statuses.length === 0) return null;
  // null 表示该调用成功；只要有任意一个成功，就说明端点可用。
  if (statuses.some((status) => status === null)) return null;
  if (statuses.every((status) => status === 404)) return 'route-missing';
  if (statuses.every((status) => status === 0)) return 'unreachable';
  return null;
}
