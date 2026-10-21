// Run: tsx src/__tests__/welcome-phishing-scenario.test.tsx

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { en } from "../locales/en";
import { zh } from "../locales/zh";
import { zhTW } from "../locales/zh-TW";

const testDir = dirname(fileURLToPath(import.meta.url));
const welcomeSource = readFileSync(resolve(testDir, "../components/Welcome.tsx"), "utf8");
const transcriptSource = readFileSync(resolve(testDir, "../components/Transcript.tsx"), "utf8");
const appSource = readFileSync(resolve(testDir, "../App.tsx"), "utf8");

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

const PHISHING_KEYS = [
  "welcome.scenariosLabel",
  "welcome.phishing.title",
  "welcome.phishing.hint",
  "welcome.phishing.prompt",
] as const;

console.log("\nwelcome phishing scenario entry");

// Every new key must exist and be non-empty in all three dictionaries.
for (const key of PHISHING_KEYS) {
  ok(en[key].length > 0, `en defines ${key}`);
  ok(zh[key].length > 0, `zh defines ${key}`);
  ok(zhTW[key].length > 0, `zh-TW defines ${key}`);
}

// The brand empty-state renders a one-click scenario entry.
ok(welcomeSource.includes('className="welcome__scenarios"'), "brand welcome renders the scenario container");
ok(
  welcomeSource.includes('className="welcome__scenario liquid-button"'),
  "scenario entry reuses the liquid-button style",
);
ok(
  /onClick=\{\(\) => \(onScenarioPrompt \?\? onPrompt\)\(t\("welcome\.phishing\.prompt"\)\)\}/.test(welcomeSource),
  "clicking the scenario entry prefills the triage prompt instead of sending",
);
ok(
  transcriptSource.includes("onScenarioPrompt={onScenarioPrompt}"),
  "transcript forwards the scenario prefill callback to the welcome entry",
);
ok(
  appSource.includes("onScenarioPrompt={handleScenarioPrefill}"),
  "app wires the scenario prefill callback into the composer draft",
);
ok(welcomeSource.includes('t("welcome.scenariosLabel")'), "scenario container uses the localized label");
ok(welcomeSource.includes('t("welcome.phishing.title")'), "scenario entry renders the localized phishing title");
ok(welcomeSource.includes('t("welcome.phishing.hint")'), "scenario entry renders the .eml upload hint");

// The hint must mention the .eml attachment in every locale.
ok(
  en["welcome.phishing.hint"].includes(".eml") &&
    zh["welcome.phishing.hint"].includes(".eml") &&
    zhTW["welcome.phishing.hint"].includes(".eml"),
  "every locale hint mentions the .eml attachment",
);

// The sent prompt must carry the phishing triage intent.
ok(/phish/i.test(en["welcome.phishing.prompt"]), "the en prompt carries the phishing triage intent");
ok(/研判|举报/.test(zh["welcome.phishing.prompt"]), "the zh prompt carries the triage/report intent");

// Regression guard: the four original example prompts stay in place.
ok(
  ["welcome.ex1", "welcome.ex2", "welcome.ex3", "welcome.ex4"].every((k) => welcomeSource.includes(`t("${k}")`)),
  "the four existing example prompts are untouched",
);

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
