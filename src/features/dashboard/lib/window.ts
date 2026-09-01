export function windowToRange(window?: string): { from?: string; to?: string } {
  if (!window || window === "all") return {};

  const days = window === "24h" ? 1 : window === "30d" ? 30 : 7;
  const to = new Date();
  const from = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  return { from: from.toISOString(), to: to.toISOString() };
}

/** Date-only `to` would exclude same-day timestamps; expand to end of day. */
export function resolveRange(from?: string, to?: string, timeWindow?: string) {
  if (from || to) {
    return {
      from: from ? startOfDay(from) : undefined,
      to: to ? endOfDay(to) : undefined,
    };
  }

  return windowToRange(timeWindow);
}

function startOfDay(value: string) {
  if (value.length <= 10) return `${value}T00:00:00.000Z`;
  return value;
}

function endOfDay(value: string) {
  if (value.length <= 10) return `${value}T23:59:59.999Z`;
  return value;
}

export function dateInputValue(value: string | null) {
  if (!value) return "";
  return value.slice(0, 10);
}

/** Keep the Insights range and active run on incident links and the back path. */
export function toQueryString(params: {
  from?: string;
  to?: string;
  window?: string;
  run?: string;
}) {
  const next = new URLSearchParams();
  if (params.run) next.set("run", params.run);
  if (params.from) next.set("from", params.from);
  if (params.to) next.set("to", params.to);
  if (params.window && params.window !== "all") next.set("window", params.window);
  const query = next.toString();
  return query ? `?${query}` : "";
}

