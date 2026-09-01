import "server-only";

import { headers } from "next/headers";

import { siteConfig } from "@/config/site";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const TEST_FROM = "GCTU-SIEM <onboarding@resend.dev>";

export function isValidEmail(value: string) {
  return EMAIL_RE.test(value.trim());
}

export function canSendAlertEmail() {
  return Boolean(process.env.RESEND_API_KEY);
}

/** First valid address wins: override → saved → env → login. */
export function resolveAlertRecipient(
  ...candidates: Array<string | null | undefined>
) {
  for (const value of candidates) {
    const trimmed = value?.trim() ?? "";
    if (trimmed && isValidEmail(trimmed)) return trimmed;
  }
  return "";
}

export async function sendAlertEmail(opts: {
  to: string;
  type: string;
  title: string;
  message: string;
  link?: string | null;
  origin?: string | null;
}): Promise<{ ok: boolean; sentTo?: string; error?: string }> {
  const apiKey = process.env.RESEND_API_KEY;
  const to = opts.to.trim();

  if (!apiKey) {
    return { ok: false, error: "Email is not configured (RESEND_API_KEY)." };
  }
  if (!isValidEmail(to)) {
    return { ok: false, error: "Invalid engineer email." };
  }

  const preferredFrom =
    process.env.ALERT_FROM_EMAIL?.trim() || TEST_FROM;
  const href = resolveHref(opts.link, opts.origin ?? (await originFromRequest()));
  const rendered = renderAlertEmail({
    type: opts.type,
    title: opts.title,
    message: opts.message,
    href,
  });

  const base = {
    subject: `[${siteConfig.name}] ${opts.title}`,
    text: rendered.text,
    html: rendered.html,
  };

  try {
    let from = preferredFrom;
    let result = await postResendEmail(apiKey, { ...base, from, to: [to] });
    if (result.ok) return { ok: true, sentTo: to };

    if (preferredFrom !== TEST_FROM && isUnverifiedFromDomain(result.error)) {
      from = TEST_FROM;
      result = await postResendEmail(apiKey, { ...base, from, to: [to] });
      if (result.ok) return { ok: true, sentTo: to };
    }

    const sandboxTo = parseSandboxRecipient(result.error);
    if (sandboxTo && sandboxTo.toLowerCase() !== to.toLowerCase()) {
      result = await postResendEmail(apiKey, {
        ...base,
        from: TEST_FROM,
        to: [sandboxTo],
      });
      if (result.ok) return { ok: true, sentTo: sandboxTo };
    }

    return { ok: false, error: result.error };
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Email send failed";
    console.error("[notifications] email error:", msg);
    return { ok: false, error: msg };
  }
}

function isUnverifiedFromDomain(message?: string) {
  if (!message) return false;
  return /domain is not verified|verify your domain/i.test(message);
}

function parseSandboxRecipient(message?: string) {
  if (!message) return "";
  const match = message.match(/your own email address \(([^)]+)\)/i);
  const email = match?.[1]?.trim() ?? "";
  return isValidEmail(email) ? email : "";
}

function sanitizeOrigin(value?: string | null) {
  const raw = value?.trim() ?? "";
  if (!raw) return "";
  try {
    const url = new URL(raw.includes("://") ? raw : `http://${raw}`);
    if (url.protocol !== "http:" && url.protocol !== "https:") return "";
    return url.origin;
  } catch {
    return "";
  }
}

async function originFromRequest() {
  try {
    const h = await headers();
    const host = h.get("x-forwarded-host") ?? h.get("host");
    if (!host) return "";
    const proto = h.get("x-forwarded-proto") ?? (host.includes("localhost") ? "http" : "https");
    return sanitizeOrigin(`${proto.split(",")[0].trim()}://${host.split(",")[0].trim()}`);
  } catch {
    return "";
  }
}

function resolveAppOrigin(preferred?: string | null) {
  const fromClient = sanitizeOrigin(preferred);
  if (fromClient) return fromClient;

  const explicit = sanitizeOrigin(process.env.NEXT_PUBLIC_APP_URL);
  if (explicit) return explicit;

  const vercel =
    process.env.VERCEL_PROJECT_PRODUCTION_URL?.trim() ||
    process.env.VERCEL_URL?.trim();
  if (vercel) return sanitizeOrigin(`https://${vercel.replace(/^https?:\/\//, "")}`);

  return "";
}

function resolveHref(link?: string | null, origin?: string | null) {
  const raw = link?.trim() ?? "";
  const base = resolveAppOrigin(origin);
  if (!raw) return base;
  if (/^https?:\/\//i.test(raw)) return raw;
  const path = raw.startsWith("/") ? raw : `/${raw}`;
  return base ? `${base}${path}` : "";
}

function ctaLabel(href: string) {
  if (href.includes("/incidents/")) return "Open incident";
  if (href.includes("live=true")) return "Open live session";
  return `Open ${siteConfig.name}`;
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const TYPE_META: Record<
  string,
  { label: string; color: string; bg: string }
> = {
  critical: { label: "Critical", color: "#e07a7a", bg: "#3a1c1c" },
  warning: { label: "Warning", color: "#d4b15a", bg: "#2e2614" },
  info: { label: "Info", color: "#60a5fa", bg: "#152033" },
  success: { label: "Complete", color: "#6fbf73", bg: "#15291a" },
};

function renderAlertEmail(opts: {
  type: string;
  title: string;
  message: string;
  href: string;
}) {
  const meta = TYPE_META[opts.type] ?? TYPE_META.info;
  const title = escapeHtml(opts.title);
  const message = escapeHtml(opts.message);
  const href = opts.href;
  const button = href ? ctaLabel(href) : "";

  const text = [
    `${siteConfig.name} · ${meta.label}`,
    "",
    opts.title,
    "",
    opts.message,
    href ? `\n${button}:\n${href}` : "",
    "",
    `— ${siteConfig.name}`,
    siteConfig.description,
  ]
    .filter(Boolean)
    .join("\n");

  const buttonHtml = href
    ? `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 16px;">
        <tr>
          <td style="border-radius:6px;background:#e0dd5b;">
            <a href="${escapeHtml(href)}" style="display:inline-block;padding:11px 18px;font-family:'IBM Plex Sans',Segoe UI,Helvetica,Arial,sans-serif;font-size:13px;font-weight:600;letter-spacing:0.01em;color:#080808;text-decoration:none;">${escapeHtml(button)}</a>
          </td>
        </tr>
      </table>
      <p style="margin:0 0 4px;font-size:11px;line-height:16px;color:#525252;">Or paste this link into your browser</p>
      <p style="margin:0;font-family:'IBM Plex Mono',ui-monospace,Menlo,monospace;font-size:11px;line-height:16px;word-break:break-all;"><a href="${escapeHtml(href)}" style="color:#e0dd5b;text-decoration:none;">${escapeHtml(href)}</a></p>`
    : `<p style="margin:0;font-size:12px;line-height:18px;color:#838383;">Open ${escapeHtml(siteConfig.name)} to review this alert.</p>`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
</head>
<body style="margin:0;padding:0;background:#111111;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#111111;padding:24px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="width:100%;max-width:560px;background:#080808;border:1px solid #1e1e1e;border-radius:10px;">
          <tr>
            <td style="padding:20px 24px 16px;border-bottom:1px solid #1e1e1e;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="font-family:'IBM Plex Sans',Segoe UI,Helvetica,Arial,sans-serif;font-size:13px;font-weight:600;letter-spacing:0.04em;color:#ffffff;">${escapeHtml(siteConfig.name)}</td>
                  <td align="right">
                    <span style="display:inline-block;padding:3px 8px;border-radius:999px;background:${meta.bg};border:1px solid ${meta.color};font-family:'IBM Plex Sans',Segoe UI,Helvetica,Arial,sans-serif;font-size:10px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:${meta.color};">${meta.label}</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:22px 24px 8px;font-family:'IBM Plex Sans',Segoe UI,Helvetica,Arial,sans-serif;">
              <h1 style="margin:0 0 10px;font-size:18px;line-height:24px;font-weight:600;color:#ffffff;">${title}</h1>
              <p style="margin:0 0 22px;font-size:14px;line-height:22px;color:#c4c4c4;">${message}</p>
              ${buttonHtml}
            </td>
          </tr>
          <tr>
            <td style="padding:16px 24px 20px;border-top:1px solid #1e1e1e;font-family:'IBM Plex Sans',Segoe UI,Helvetica,Arial,sans-serif;font-size:11px;line-height:16px;color:#525252;">
              ${escapeHtml(siteConfig.description)} · Sent from ${escapeHtml(siteConfig.name)}
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

  return { text, html };
}

async function postResendEmail(
  apiKey: string,
  body: { from: string; to: string[]; subject: string; text: string; html?: string },
): Promise<{ ok: boolean; error?: string }> {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (res.ok) return { ok: true };

  const raw = await res.text();
  console.error("[notifications] email failed:", res.status, raw);
  let detail = "Email provider rejected the message.";
  try {
    const parsed = JSON.parse(raw) as { message?: string };
    if (parsed.message) detail = parsed.message;
  } catch {
    /* keep fallback */
  }
  return { ok: false, error: detail };
}
