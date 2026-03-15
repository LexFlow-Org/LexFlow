/**
 * LexFlow Orchestrator Agent
 *
 * Main entry point that coordinates all 4 specialized agents.
 * The orchestrator delegates tasks to the right agent based on the prompt.
 *
 * Usage:
 *   npx tsx src/orchestrator.ts "Add a new Contacts page with search"
 *   npx tsx src/orchestrator.ts "Debug why vault unlock fails on second attempt"
 *   npx tsx src/orchestrator.ts "Scan the app for dead code and clean everything"
 */

import type { Options, SDKResultMessage } from "@anthropic-ai/claude-agent-sdk";
import { query } from "@anthropic-ai/claude-agent-sdk";
import { AGENTS } from "./definitions.js";

const prompt = process.argv.slice(2).join(" ");

if (!prompt) {
  console.error(`
╔══════════════════════════════════════════════════════════════════╗
║                 LexFlow Agent Orchestrator                      ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Usage:                                                          ║
║    npm run orchestrator -- "your task description"               ║
║                                                                  ║
║  Available agents (auto-selected by orchestrator):               ║
║    • frontend-writer  — React/JSX UI development                ║
║    • backend-writer   — Rust/Tauri backend development          ║
║    • nasa-debugger    — Mission-critical debugging               ║
║    • app-restructurer — Dead code cleanup & restructuring        ║
║                                                                  ║
║  Examples:                                                       ║
║    npm run orchestrator -- "Add a search bar to PracticesPage"   ║
║    npm run orchestrator -- "Create a command for PDF merge"      ║
║    npm run orchestrator -- "Debug the biometric login flow"      ║
║    npm run orchestrator -- "Full codebase scan and cleanup"      ║
║                                                                  ║
║  Run individual agents:                                          ║
║    npm run frontend  -- "your task"                              ║
║    npm run backend   -- "your task"                              ║
║    npm run debugger  -- "your task"                              ║
║    npm run cleaner   -- "your task"                              ║
║                                                                  ║
║  Run all agents sequentially:                                    ║
║    npm run all                                                   ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`);
  process.exit(1);
}

const CWD = new URL("../../", import.meta.url).pathname.replace(/\/$/, "");

console.log(`\n🔷 LexFlow Orchestrator starting...`);
console.log(`📁 Working directory: ${CWD}`);
console.log(`📝 Task: ${prompt}\n`);

async function main() {
  const options: Options = {
    cwd: CWD,
    allowedTools: ["Read", "Write", "Edit", "Glob", "Grep", "Bash", "Agent"],
    agents: AGENTS,
    permissionMode: "default",
    maxTurns: 50,
  };

  for await (const message of query({
    prompt: `You are the LexFlow Orchestrator. You coordinate 4 specialized agents
to develop, debug, and maintain the LexFlow application.

You have these agents available:
- **frontend-writer**: For React/JSX UI work (components, pages, stores, styling)
- **backend-writer**: For Rust/Tauri backend work (commands, encryption, plugins)
- **nasa-debugger**: For debugging backend issues and frontend-backend bridge problems
- **app-restructurer**: For scanning dead code, cleaning up, and restructuring

RULES:
1. Analyze the task and delegate to the right agent(s)
2. If a task spans frontend AND backend, use both agents in sequence:
   - Backend first (create the Rust command)
   - Frontend second (create the UI + bridge)
3. After any code change, use nasa-debugger to verify
4. For cleanup tasks, use app-restructurer
5. Report results clearly to the user

CURRENT TASK: ${prompt}`,
    options,
  })) {
    if (message.type === "result" && message.subtype === "success") {
      console.log("\n" + (message as SDKResultMessage & { result: string }).result);
    }
  }
}

main().catch((err) => {
  console.error("Orchestrator error:", err);
  process.exit(1);
});
