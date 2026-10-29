// Run: tsx src/__tests__/tir-availability.test.ts
// 覆盖 TIR 三端点降级后的可用性判定：路由缺失 / 服务不可达 / 正常或鉴权失败不提示。

import { summarizeTirAvailability } from "../lib/tirAvailability";

let passed = 0;
let failed = 0;

function eq(actual: unknown, expected: unknown, label: string) {
  if (actual === expected) {
    process.stdout.write(`  PASS  ${label}\n`);
    passed += 1;
  } else {
    process.stdout.write(`  FAIL  ${label} (expected ${String(expected)}, got ${String(actual)})\n`);
    failed += 1;
  }
}

console.log("\nTIR availability");

eq(
  summarizeTirAvailability([404, 404, 404]),
  "route-missing",
  "三个端点全部 404 → 判定为路由未部署",
);
eq(
  summarizeTirAvailability([0, 0, 0]),
  "unreachable",
  "三个端点全部不可达 → 判定为 TIR 服务不可达",
);
eq(
  summarizeTirAvailability([null, 404, 404]),
  null,
  "任意一个端点成功时不提示缺失",
);
eq(
  summarizeTirAvailability([401, 401, 401]),
  null,
  "鉴权失败交由全局登出处理，不提示路由缺失",
);
eq(
  summarizeTirAvailability([404, 0, 404]),
  null,
  "混合失败（404 + 不可达）不做单一归因",
);
eq(summarizeTirAvailability([]), null, "空状态不提示");

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
