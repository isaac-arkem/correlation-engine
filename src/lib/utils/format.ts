function pad(value: number) {
  return String(value).padStart(2, "0");
}

function toDate(value: string | Date) {
  return value instanceof Date ? value : new Date(value);
}

/** UTC, hydration-safe. Same string on server and client. */
export function formatDateTime(value: string | Date) {
  const date = toDate(value);
  if (Number.isNaN(date.getTime())) return "—";

  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`;
}

export function formatDate(value: string | Date) {
  const date = toDate(value);
  if (Number.isNaN(date.getTime())) return "—";

  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}`;
}

export function formatNumber(value: number) {
  return value.toLocaleString("en-US");
}
