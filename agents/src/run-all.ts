/**
 * Run all LexFlow agents in sequence
 *
 * Executes a full development cycle:
 * 1. App Restructurer — scan & clean dead code
 * 2. Backend Writer — implement/improve backend
 * 3. Frontend Writer — implement/improve frontend
 * 4. NASA Debugger — verify everything works
 *
 * Usage:
 *   npx tsx src/run-all.ts
 */

import type { Options, SDKResultMessage } from "@anthropic-ai/claude-agent-sdk";
import { query } from "@anthropic-ai/claude-agent-sdk";
import { AGENTS } from "./definitions.js";

const CWD = new URL("../../", import.meta.url).pathname.replace(/\/$/, "");

interface AgentRun {
  name: string;
  icon: string;
  task: string;
}

const pipeline: AgentRun[] = [
  {
    name: "app-restructurer",
    icon: "🧹",
    task: `Perform a complete scan of the LexFlow codebase:
1. Find ALL dead code (unused functions, exports, imports, components)
2. Find ALL unused files (images, fonts, configs)
3. Find ALL duplicated code patterns
4. Report a structured list of findings with severity and recommended action
Do NOT delete anything yet — just report findings.`,
  },
  {
    name: "backend-writer",
    icon: "⚙️",
    task: `Review the LexFlow Rust backend (src-tauri/src/lib.rs) for:
1. Code quality: proper error handling, no unwrap() in command handlers
2. Performance: unnecessary clones, allocation patterns
3. Security: input validation, path traversal checks
4. Completeness: are all commands properly registered?
Report any improvements needed but only make safe, non-breaking changes.`,
  },
  {
    name: "frontend-writer",
    icon: "🎨",
    task: `Review the LexFlow React frontend (client/src/) for:
1. Component quality: proper error boundaries, loading states
2. Consistency: do all pages follow the same patterns?
3. Accessibility: aria labels, keyboard navigation
4. tauri-api.js: are all exports used? Are there missing bridge functions?
Report findings and make safe improvements only.`,
  },
  {
    name: "nasa-debugger",
    icon: "🚀",
    task: `Perform a NASA-grade bridge verification of LexFlow:
1. For EVERY export in client/src/tauri-api.js, verify the matching Rust command exists
2. For EVERY Rust command in generate_handler![], verify it's exported in tauri-api.js
3. Check argument name alignment (JS camelCase keys must match Rust parameter names)
4. Check return type alignment (Rust Result<T> → JS Promise<T>)
5. Report any mismatches as CRITICAL issues`,
  },
];

console.log(`
╔══════════════════════════════════════════════════════════════════╗
║              LexFlow Full Agent Pipeline                         ║
╠══════════════════════════════════════════════════════════════════╣
║  Running ${pipeline.length} agents in sequence...                             ║
╚══════════════════════════════════════════════════════════════════╝
`);

async function runAgent(run: AgentRun, index: number) {
  const agent = AGENTS[run.name];
  console.log(`\n${"═".repeat(64)}`);
  console.log(`${run.icon} [${index + 1}/${pipeline.length}] ${run.name}`);
  console.log(`${"═".repeat(64)}\n`);

  const options: Options = {
    cwd: CWD,
    allowedTools: agent.tools as string[],
    systemPrompt: agent.prompt,
    permissionMode: "default",
    maxTurns: 25,
  };

  for await (const message of query({ prompt: run.task, options })) {
    if (message.type === "result" && message.subtype === "success") {
      console.log("\n" + (message as SDKResultMessage & { result: string }).result);
    }
  }

  console.log(`\n✅ ${run.name} completed`);
}

async function main() {
  const startTime = Date.now();

  for (let i = 0; i < pipeline.length; i++) {
    await runAgent(pipeline[i], i);
  }

  const elapsed = ((Date.now() - startTime) / 1000 / 60).toFixed(1);
  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  ✅ Full pipeline completed in ${elapsed} minutes                     ║
╚══════════════════════════════════════════════════════════════════╝
`);
}

main().catch((err) => {
  console.error("Pipeline error:", err);
  process.exit(1);
});
