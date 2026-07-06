#!/usr/bin/env bun
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { APP_VERSION } from "../version.js";
import { getOperationByMcp, type Profile } from "../services/registry.js";
import type { ApiPrincipal } from "../server/auth.js";
import { registerStandardTools } from "./tools/standard.js";
import { registerStorageTools } from "./tools/storage.js";
import { registerDomainTools } from "./tools/domain.js";

export interface BuildServerOptions {
  principal?: ApiPrincipal;
}

export function getProfile(): Profile {
  const env = (process.env["CONTROLS_PROFILE"] || process.env["HASNA_CONTROLS_PROFILE"])?.toLowerCase();
  if (env === "minimal" || env === "standard" || env === "full") return env;
  return "full";
}

/** Whether a domain tool (by its bare mcp name) is enabled under a profile. */
export function domainToolEnabled(mcpName: string, profile: Profile = getProfile()): boolean {
  const op = getOperationByMcp(mcpName);
  if (!op) return false;
  return op.profiles.includes(profile);
}

/** Build a fully-wired MCP server. `principal` binds the caller's scopes (HTTP). */
export function buildServer(opts?: BuildServerOptions): McpServer {
  const server = new McpServer({ name: "controls", version: APP_VERSION });
  const profile = getProfile();
  // The 4 standard tools + 4 storage tools are always registered (§5.5).
  registerStandardTools(server, () => true);
  registerStorageTools(server, opts?.principal);
  registerDomainTools(server, opts?.principal, (name) => domainToolEnabled(name, profile));
  return server;
}

function hasFlag(...flags: string[]): boolean {
  return flags.some((f) => process.argv.includes(f));
}

function printHelp(): void {
  console.log(`Usage: controls-mcp [options]

Start the @hasna/controls MCP server.

Options:
  --stdio          Use stdio transport (fallback for ad-hoc local clients)
  --http           Use Streamable HTTP transport (shared, per-caller bearer auth)
  --port <port>    HTTP port (implies --http; default 8886)
  -V, --version    output the version number
  -h, --help       display help for command

Environment:
  MCP_STDIO=1                 Force stdio transport
  MCP_HTTP=1                  Use Streamable HTTP transport
  MCP_HTTP_PORT=<port>        HTTP port
  CONTROLS_PROFILE=<profile>  Tool profile filter: minimal|standard|full
  HASNA_CONTROLS_MCP_AUTH=off Disable MCP bearer auth (loopback + local mode only)`);
}

async function main(): Promise<void> {
  if (hasFlag("--version", "-V")) {
    console.log(APP_VERSION);
    return;
  }
  if (hasFlag("--help", "-h")) {
    printHelp();
    return;
  }

  const { isHttpMode, isStdioMode, resolveHttpPort, startHttpServer } = await import("./http.js");
  if (isHttpMode() && !isStdioMode()) {
    await startHttpServer(resolveHttpPort());
    return;
  }
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

if (import.meta.main) {
  main().catch((err) => {
    console.error("Fatal error in controls MCP server:", err);
    process.exit(1);
  });
}
