import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { resolveStorageMode } from "../config.js";
import { authenticateToken, bearerFromHeader, type ApiPrincipal } from "../server/auth.js";
import { buildServer } from "./index.js";

export const DEFAULT_MCP_HTTP_PORT = 8886;
export const MCP_HTTP_NAME = "controls";

export function isHttpMode(): boolean {
  return process.argv.includes("--http") || process.env["MCP_HTTP"] === "1";
}

export function isStdioMode(): boolean {
  return process.argv.includes("--stdio") || process.env["MCP_STDIO"] === "1";
}

export function resolveHttpPort(defaultPort = DEFAULT_MCP_HTTP_PORT): number {
  const portFlag = process.argv.find((arg) => arg === "--port" || arg.startsWith("--port="));
  if (portFlag) {
    if (portFlag.includes("=")) {
      const parsed = Number.parseInt(portFlag.split("=")[1] ?? "", 10);
      if (Number.isFinite(parsed) && parsed > 0) return parsed;
    } else {
      const idx = process.argv.indexOf(portFlag);
      const parsed = Number.parseInt(process.argv[idx + 1] ?? "", 10);
      if (Number.isFinite(parsed) && parsed > 0) return parsed;
    }
  }
  const envPort = Number.parseInt(process.env["MCP_HTTP_PORT"] ?? "", 10);
  if (Number.isFinite(envPort) && envPort > 0) return envPort;
  return defaultPort;
}

function isLoopbackHost(host: string): boolean {
  return host === "127.0.0.1" || host === "localhost" || host === "::1";
}

/**
 * MCP HTTP auth (§5.1a). Fail-closed by default: a bearer token is required on
 * every /mcp request unless HASNA_CONTROLS_MCP_AUTH=off is set AND the server is
 * bound to loopback in local mode.
 */
export function mcpAuthRequired(host: string): boolean {
  const off = (process.env["HASNA_CONTROLS_MCP_AUTH"] || process.env["CONTROLS_MCP_AUTH"]) === "off";
  if (off && isLoopbackHost(host) && resolveStorageMode() === "local") return false;
  return true;
}

export function healthResponse(name = MCP_HTTP_NAME): Response {
  return Response.json({ status: "ok", name });
}

export async function handleMcpHttpRequest(
  req: Request,
  opts: { host: string; createServer?: (principal?: ApiPrincipal) => McpServer } = { host: "127.0.0.1" },
): Promise<Response> {
  let principal: ApiPrincipal | undefined;
  if (mcpAuthRequired(opts.host)) {
    const token = bearerFromHeader(req.headers.get("Authorization"));
    const authed = authenticateToken(token);
    if (!authed) {
      return Response.json(
        { code: "UNAUTHORIZED", message: "Invalid or missing MCP bearer token.", suggestion: "Send Authorization: Bearer <token>." },
        { status: 401 },
      );
    }
    principal = authed;
  }

  const create = opts.createServer ?? ((p?: ApiPrincipal) => buildServer(p ? { principal: p } : undefined));
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  const server = create(principal);
  await server.connect(transport);
  return transport.handleRequest(req);
}

export async function startHttpServer(
  port: number,
  options?: { host?: string; name?: string },
): Promise<ReturnType<typeof Bun.serve>> {
  const host = options?.host ?? "127.0.0.1";
  const name = options?.name ?? MCP_HTTP_NAME;

  const server = Bun.serve({
    hostname: host,
    port,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === "/health" && req.method === "GET") return healthResponse(name);
      if (url.pathname === "/mcp") return handleMcpHttpRequest(req, { host });
      return Response.json({ error: "Not found" }, { status: 404 });
    },
  });

  console.error(`controls-mcp HTTP listening on http://${host}:${port}/mcp (auth ${mcpAuthRequired(host) ? "required" : "off"})`);
  return server;
}
