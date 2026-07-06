import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerStandardTools } from "../../src/mcp/tools/standard.js";
import { registerStorageTools } from "../../src/mcp/tools/storage.js";
import { registerDomainTools } from "../../src/mcp/tools/domain.js";
import { domainToolEnabled, getProfile } from "../../src/mcp/index.js";
import type { ApiPrincipal } from "../../src/server/auth.js";
import type { Profile } from "../../src/services/registry.js";

export type ToolHandler = (args: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }>; structuredContent?: unknown; isError?: boolean }>;

export interface CapturedTools {
  names: string[];
  handlers: Map<string, ToolHandler>;
}

/** Capture registered MCP tools by faking the McpServer.tool() surface. */
export function captureTools(principal?: ApiPrincipal, profile: Profile = getProfile()): CapturedTools {
  const handlers = new Map<string, ToolHandler>();
  const fake = {
    tool(name: string, _desc: string, _shape: unknown, cb: ToolHandler) {
      handlers.set(name, cb);
    },
  } as unknown as McpServer;

  registerStandardTools(fake, () => true);
  registerStorageTools(fake, principal);
  registerDomainTools(fake, principal, (n) => domainToolEnabled(n, profile));
  return { names: [...handlers.keys()], handlers };
}

export async function callTool(tools: CapturedTools, name: string, args: Record<string, unknown> = {}): Promise<unknown> {
  const handler = tools.handlers.get(name);
  if (!handler) throw new Error(`tool not registered: ${name}`);
  const result = await handler(args);
  const text = result.content?.[0]?.text ?? "null";
  return JSON.parse(text) as unknown;
}
