import { toErrorEnvelope } from "../types/index.js";

export interface ToolResult {
  [x: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

/** Wrap a successful value as an MCP tool result (JSON text + structuredContent). */
export function ok(value: unknown): ToolResult {
  const structured = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : { result: value };
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    structuredContent: structured,
  };
}

/** Wrap an error as an MCP tool result with the shared { code, message, suggestion } envelope. */
export function fail(error: unknown): ToolResult {
  const env = toErrorEnvelope(error);
  return {
    content: [{ type: "text", text: JSON.stringify(env) }],
    structuredContent: env as unknown as Record<string, unknown>,
    isError: true,
  };
}
