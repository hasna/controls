export type ListSortOrder = "asc" | "desc";

export interface ListPagination {
  total: number;
  returned: number;
  limit: number | null;
  offset: number;
  has_more: boolean;
  sort: string;
  order: ListSortOrder;
}

export interface ListEnvelope<T> {
  data: T[];
  pagination: ListPagination;
}

export interface ListQueryOptions {
  default_sort: string;
  allowed_sorts: string[];
  max_limit?: number;
}

export class InvalidListQueryError extends Error {
  static code = "INVALID_LIST_QUERY";
  static suggestion = "Use a supported sort field and positive integer limit/offset.";
  code = InvalidListQueryError.code;
  constructor(message: string) {
    super(message);
    this.name = "InvalidListQueryError";
  }
}

const listQueryKeys = new Set(["limit", "offset", "page", "page_size", "sort", "order"]);

export function listQueryResponse<T extends object>(url: URL, items: T[], options: ListQueryOptions): T[] | ListEnvelope<T> {
  if (!hasListQuery(url)) return items;

  const sort = parseSort(url, options);
  const ordered = [...items].sort((left, right) => compareValues(fieldValue(left, sort.field), fieldValue(right, sort.field), sort.order));
  const limit = parseLimit(url, options.max_limit ?? 500);
  const offset = parseOffset(url, limit);
  const data = limit === null ? ordered.slice(offset) : ordered.slice(offset, offset + limit);

  return {
    data,
    pagination: {
      total: ordered.length,
      returned: data.length,
      limit,
      offset,
      has_more: offset + data.length < ordered.length,
      sort: sort.field,
      order: sort.order,
    },
  };
}

function hasListQuery(url: URL): boolean {
  return Array.from(url.searchParams.keys()).some((key) => listQueryKeys.has(key));
}

function parseSort(url: URL, options: ListQueryOptions): { field: string; order: ListSortOrder } {
  const rawSort = url.searchParams.get("sort") || options.default_sort;
  const requestedDesc = rawSort.startsWith("-");
  const field = requestedDesc ? rawSort.slice(1) : rawSort;
  if (!options.allowed_sorts.includes(field)) {
    throw new InvalidListQueryError(`Unsupported sort field: ${field}. Allowed fields: ${options.allowed_sorts.join(", ")}.`);
  }
  const orderParam = url.searchParams.get("order")?.toLowerCase();
  if (orderParam && orderParam !== "asc" && orderParam !== "desc") {
    throw new InvalidListQueryError("order must be asc or desc.");
  }
  return { field, order: (orderParam as ListSortOrder | null) || (requestedDesc ? "desc" : "asc") };
}

function parseLimit(url: URL, maxLimit: number): number | null {
  const raw = url.searchParams.get("limit") || url.searchParams.get("page_size");
  if (!raw) return url.searchParams.has("page") ? Math.min(50, maxLimit) : null;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1) throw new InvalidListQueryError("limit/page_size must be a positive integer.");
  return Math.min(value, maxLimit);
}

function parseOffset(url: URL, limit: number | null): number {
  const rawOffset = url.searchParams.get("offset");
  if (rawOffset !== null) {
    const value = Number(rawOffset);
    if (!Number.isInteger(value) || value < 0) throw new InvalidListQueryError("offset must be a non-negative integer.");
    return value;
  }
  const rawPage = url.searchParams.get("page");
  if (!rawPage) return 0;
  const page = Number(rawPage);
  if (!Number.isInteger(page) || page < 1) throw new InvalidListQueryError("page must be a positive integer.");
  return (page - 1) * (limit ?? 50);
}

function compareValues(left: unknown, right: unknown, order: ListSortOrder): number {
  const direction = order === "asc" ? 1 : -1;
  const a = normalizeValue(left);
  const b = normalizeValue(right);
  if (a < b) return -1 * direction;
  if (a > b) return 1 * direction;
  return 0;
}

function fieldValue(item: object, field: string): unknown {
  return (item as Record<string, unknown>)[field];
}

function normalizeValue(value: unknown): string | number {
  if (typeof value === "number") return value;
  if (typeof value === "boolean") return value ? 1 : 0;
  if (value === null || value === undefined) return "";
  return String(value).toLowerCase();
}
