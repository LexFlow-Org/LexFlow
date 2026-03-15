/**
 * Run a single LexFlow agent directly
 *
 * Usage:
 *   npx tsx src/run-agent.ts frontend-writer "Add a filter dropdown to AgendaPage"
 *   npx tsx src/run-agent.ts backend-writer "Create a command to export contacts as CSV"
 *   npx tsx src/run-agent.ts nasa-debugger "Debug why notifications don't fire on macOS"
 *   npx tsx src/run-agent.ts app-restructurer "Scan for dead code in client/src/components"
 */

import type { Options, SDKResultMessage } from "@anthropic-ai/claude-agent-sdk";
import { query } from "@anthropic-ai/claude-agent-sdk";
import { AGENTS } from "./definitions.js";

const agentName = process.argv[2];
const prompt = process.argv.slice(3).join(" ");

const validAgents = Object.keys(AGENTS);

if (!agentName || !validAgents.includes(agentName)) {
  console.error(`
Usage: npx tsx src/run-agent.ts <agent-name> "task description"

Available agents:
  ${validAgents.map((a) => `• ${a}`).join("\n  ")}
`);
  process.exit(1);
}

if (!prompt) {
  console.error(`Please provide a task description for ${agentName}`);
  process.exit(1);
}

const agent = AGENTS[agentName];
const CWD = new URL("../../", import.meta.url).pathname.replace(/\/$/, "");

const AGENT_ICONS: Record<string, string> = {
  "frontend-writer": "🎨",
  "backend-writer": "⚙️",
  "nasa-debugger": "🚀",
  "app-restructurer": "🧹",
};

console.log(`\n${AGENT_ICONS[agentName] || "🤖"} Agent: ${agentName}`);
console.log(`📁 Working directory: ${CWD}`);
console.log(`📝 Task: ${prompt}\n`);

async function main() {
  const options: Options = {
    cwd: CWD,
    allowedTools: agent.tools as string[],
    systemPrompt: agent.prompt,
    permissionMode: "default",
    maxTurns: 30,
  };

  for await (const message of query({ prompt, options })) {
    if (message.type === "result" && message.subtype === "success") {
      console.log("\n" + (message as SDKResultMessage & { result: string }).result);
    }
  }
}

main().catch((err) => {
  console.error(`${agentName} error:`, err);
  process.exit(1);
});
