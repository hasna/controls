import { OPERATIONS, type OperationDef, type OperationField } from "../services/registry.js";
import { requiredScopeForAction } from "../server/auth.js";
import { APP_VERSION } from "../version.js";

/** OpenAPI 3.1 document generated from the shared operation registry (§6.3). */
export function openApiDocument(): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};

  for (const def of OPERATIONS) {
    const openapiPath = def.rest.path.replace(/:([a-zA-Z_]+)/g, "{$1}");
    const method = def.rest.method.toLowerCase();
    paths[openapiPath] ??= {};
    (paths[openapiPath] as Record<string, unknown>)[method] = operationObject(def);
  }

  return {
    openapi: "3.1.0",
    info: {
      title: "@hasna/controls",
      version: APP_VERSION,
      description:
        "Spend-authorization/approval control plane: per-entity/per-agent caps, counterparty allowlists, tiered approval thresholds, segregation-of-duties, emergency freeze, and an append-only tamper-evident money audit.",
    },
    servers: [{ url: "http://127.0.0.1:3482", description: "local serve" }],
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer" },
      },
    },
    security: [{ bearerAuth: [] }],
    paths,
  };
}

function operationObject(def: OperationDef): Record<string, unknown> {
  const pathFields = def.fields.filter((f) => def.pathParams.includes(f.name));
  const nonPath = def.fields.filter((f) => !def.pathParams.includes(f.name));
  const parameters: Array<Record<string, unknown>> = [];

  for (const p of def.pathParams) {
    const field = pathFields.find((f) => f.name === p);
    parameters.push({
      name: p,
      in: "path",
      required: true,
      description: field?.description ?? `${p} path parameter`,
      schema: { type: field?.type === "integer" ? "integer" : "string" },
    });
  }

  const obj: Record<string, unknown> = {
    operationId: def.op.replace(/\./g, "_"),
    summary: def.summary,
    tags: [def.cli.namespace],
    "x-scope": requiredScopeForAction(def.action),
    parameters,
    responses: {
      "200": { description: "Success" },
      "401": { description: "Unauthorized" },
      "403": { description: "Permission denied" },
      "422": { description: "Control violation (cap/allowlist/freeze/SoD)" },
    },
  };

  if (def.rest.method === "POST" || def.rest.method === "PATCH") {
    obj.requestBody = {
      required: nonPath.some((f) => f.required),
      content: { "application/json": { schema: jsonSchema(nonPath) } },
    };
  } else if (nonPath.length > 0) {
    for (const f of nonPath) {
      parameters.push({
        name: f.name,
        in: "query",
        required: false,
        description: f.description,
        schema: { type: f.type },
      });
    }
  }

  return obj;
}

function jsonSchema(fields: OperationField[]): Record<string, unknown> {
  const properties: Record<string, unknown> = {};
  const required: string[] = [];
  for (const f of fields) {
    properties[f.name] = { type: f.type, description: f.description };
    if (f.required) required.push(f.name);
  }
  return { type: "object", properties, ...(required.length > 0 ? { required } : {}) };
}
