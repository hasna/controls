import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { ok } from "../compact.js";
import { APP_VERSION } from "../../version.js";

interface AgentRecord {
  name: string;
  registered_at: string;
  focus?: { entity_id?: string };
}

const agents = new Map<string, AgentRecord>();

/**
 * The four fleet-standard MCP tools with identical semantics across apps
 * (§5.4). `register_agent` only *names* a caller — it does NOT authenticate it;
 * authentication is the bearer token enforced at the HTTP transport (§5.1a).
 */
export function registerStandardTools(server: McpServer, shouldRegister: (name: string) => boolean): void {
  if (shouldRegister("register_agent")) {
    server.tool(
      "register_agent",
      "Register/identify the calling agent by name (naming only — does not authenticate).",
      { name: z.string().describe("Agent name/handle."), role: z.string().optional().describe("Advisory role label.") },
      async ({ name }) => {
        const record: AgentRecord = { name, registered_at: new Date().toISOString() };
        agents.set(name, record);
        return ok({ registered: true, agent: record, app: "controls" });
      },
    );
  }

  if (shouldRegister("heartbeat")) {
    server.tool(
      "heartbeat",
      "Liveness heartbeat for the controls MCP server.",
      { name: z.string().optional().describe("Agent name.") },
      async ({ name }) => ok({ status: "ok", app: "controls", version: APP_VERSION, name: name ?? null, at: new Date().toISOString() }),
    );
  }

  if (shouldRegister("set_focus")) {
    server.tool(
      "set_focus",
      "Set the calling agent's default entity focus.",
      { name: z.string().describe("Agent name."), entity_id: z.string().describe("Entity UUID to focus on.") },
      async ({ name, entity_id }) => {
        const record = agents.get(name) ?? { name, registered_at: new Date().toISOString() };
        record.focus = { entity_id };
        agents.set(name, record);
        return ok({ focus_set: true, agent: name, entity_id });
      },
    );
  }

  if (shouldRegister("send_feedback")) {
    server.tool(
      "send_feedback",
      "Send freeform feedback about the controls app to the operators.",
      { message: z.string().describe("Feedback message."), severity: z.enum(["info", "warning", "critical"]).optional() },
      async ({ message, severity }) => ok({ received: true, severity: severity ?? "info", chars: message.length }),
    );
  }
}
