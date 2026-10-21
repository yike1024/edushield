// Run: tsx src/__tests__/statusbar-workspace.test.tsx

import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { StatusBar, memoryCompilerTooltip } from "../components/StatusBar";
import { LocaleProvider } from "../lib/i18n";
import { DEFAULT_STATUS_BAR_ITEMS, normalizeStatusBarItems } from "../lib/statusBarItems";
import { en, type DictKey } from "../locales/en";
import type { MemoryCompilerStats } from "../lib/types";

const enT = (key: DictKey): string => en[key] ?? key;

let passed = 0;
let failed = 0;

function ok(value: boolean, label: string) {
  if (value) {
    process.stdout.write(`  PASS  ${label}\n`);
    passed += 1;
  } else {
    process.stdout.write(`  FAIL  ${label}\n`);
    failed += 1;
  }
}

function renderStatusBar(props: Partial<Parameters<typeof StatusBar>[0]> = {}): string {
  return renderToStaticMarkup(
    <LocaleProvider>
      <StatusBar
        context={{ used: 0, window: 0, sessionTokens: 0 }}
        running={false}
        {...props}
      />
    </LocaleProvider>,
  );
}

console.log("\nstatus bar workspace");

{
  const defaultItems = DEFAULT_STATUS_BAR_ITEMS as readonly string[];
  ok(defaultItems.includes("workspace"), "workspace is a default configurable status item");
  ok(defaultItems.includes("git_branch"), "git branch is a default configurable status item");
  ok(
    normalizeStatusBarItems(["git_branch", "workspace", "cache"]).join(",") === "git_branch,workspace,cache",
    "workspace items preserve configured order",
  );
}

{
  const propsWithLegacySandbox = {
    workspacePath: "/workspace/repo",
    workspaceName: "repo",
    sandboxPath: "/sandbox/repo",
    gitBranch: "feature/meta",
  };
  const html = renderStatusBar(propsWithLegacySandbox);
  ok(html.includes("workspace/repo"), "workspace chip uses workspace path");
  ok(!html.includes("sandbox/repo"), "workspace chip does not display sandbox path");
  ok(html.includes("feature/meta"), "git branch remains visible");
}

{
  const html = renderStatusBar({
    items: ["cache"],
    workspacePath: "/workspace/repo",
    workspaceName: "repo",
    gitBranch: "feature/meta",
  });
  ok(!html.includes("workspace/repo"), "workspace can be hidden by status item config");
  ok(!html.includes("feature/meta"), "git branch can be hidden by status item config");
}

{
  const html = renderStatusBar({
    items: ["git_branch", "workspace"],
    workspacePath: "/workspace/repo",
    workspaceName: "repo",
    gitBranch: "feature/meta",
  });
  ok(html.indexOf("feature/meta") >= 0 && html.indexOf("workspace/repo") >= 0, "workspace and git branch render as configured items");
  ok(html.indexOf("feature/meta") < html.indexOf("workspace/repo"), "workspace items follow configured order");
}

{
  const html = renderStatusBar({ items: ["model"] });
  ok(!html.includes("YOLO"), "status bar renders only configured status items, not mode indicators");
  ok(!html.includes("后台作业") && !html.includes("Background jobs"), "status bar omits non-configurable job indicators");
}

{
  const defaultItems = DEFAULT_STATUS_BAR_ITEMS as readonly string[];
  ok(!defaultItems.includes("autoresearch"), "autoresearch is not a configurable status bar UI item");
}

{
  const defaultItems = DEFAULT_STATUS_BAR_ITEMS as readonly string[];
  ok(defaultItems.includes("memory"), "memory is a default configurable status bar item");
  ok(
    normalizeStatusBarItems(["balance", "memory"]).join(",") === "balance,memory",
    "memory item preserves configured order",
  );
}

{
  const memoryCompilerStats: MemoryCompilerStats = {
    injected: true,
    usefulIR: true,
    compiledTokens: 1200,
    irOverheadTokens: 40,
    memoryReferences: 3,
    constraints: 2,
    riskNotes: 0,
    executionSteps: 5,
    totalNodes: 30,
    highSignalNodes: 8,
    toolResultNodes: 4,
    decisionNodes: 3,
    strategyCount: 1,
    learningCount: 0,
  };
  const html = renderStatusBar({
    items: ["memory"],
    memoryCompilerStats,
  });
  ok(html.includes("3"), "memory status shows reference count when injected");
  const tooltipHtml = renderToStaticMarkup(
    <span>{memoryCompilerTooltip(enT, memoryCompilerStats)}</span>,
  );
  ok(tooltipHtml.includes("1,200"), "memory tooltip shows compiled tokens");
  ok(!html.includes("suppressed"), "injected memory is not labelled suppressed");
}

{
  const memoryCompilerStats: MemoryCompilerStats = {
    injected: false,
    usefulIR: false,
    compiledTokens: 800,
    irOverheadTokens: 20,
    memoryReferences: 0,
    constraints: 1,
    riskNotes: 1,
    executionSteps: 3,
    totalNodes: 10,
    highSignalNodes: 0,
    toolResultNodes: 0,
    decisionNodes: 2,
    strategyCount: 0,
    learningCount: 0,
  };
  const html = renderStatusBar({
    items: ["memory"],
    memoryCompilerStats,
  });
  ok(html.includes("suppressed"), "suppressed memory is labelled suppressed");
  const tooltipHtml = renderToStaticMarkup(
    <span>{memoryCompilerTooltip(enT, memoryCompilerStats)}</span>,
  );
  ok(tooltipHtml.includes("800"), "suppressed memory tooltip still shows compiled tokens");
}

{
  const html = renderStatusBar({ items: ["memory"] });
  ok(!html.includes("statusbar__memory"), "memory metric is hidden when no compiler stats are available");
}

console.log(`\n${passed} passed, ${failed} failed, ${passed + failed} total`);
if (failed > 0) process.exit(1);
