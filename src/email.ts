import { getSetting, getSecretSetting } from './settings.js';

// Outbound mail via the Cloudflare Email Service REST API — a single fetch, no
// SDK. Interim path: a centralized mailer app (own project) takes over later, so
// everything goes through this one sendEmail() seam. Config lives in admin-editable
// settings: mail_from + cf_account_id (plain), cf_api_token (sealed).
// `cf_api_base` is a hidden override for tests/mocks (never surfaced in the UI).

export interface SendEmailArgs {
  to: string;
  subject: string;
  html: string;
  text: string;
}
export type SendResult = { ok: true } | { ok: false; reason: string; detail?: string };

export async function sendEmail(args: SendEmailArgs): Promise<SendResult> {
  const [fromAddr, siteName, accountId, token, apiBase] = await Promise.all([
    getSetting('mail_from'),
    getSetting('site_name', 'DreamSSO'),
    getSetting('cf_account_id'),
    getSecretSetting('cf_api_token'),
    getSetting('cf_api_base', 'https://api.cloudflare.com'),
  ]);
  if (!fromAddr || !accountId || !token) return { ok: false, reason: 'not_configured' };
  // Named sender (RFC 5322 name-addr): recipients see `Site Name <no-reply@…>`
  // instead of a bare address. Display name = the site_name setting, quoted.
  const from = siteName ? `"${siteName.replace(/[\\"]/g, '\\$&')}" <${fromAddr}>` : fromAddr;

  let r: Response;
  try {
    r = await fetch(`${apiBase}/client/v4/accounts/${encodeURIComponent(accountId)}/email/sending/send`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ from, to: args.to, subject: args.subject, html: args.html, text: args.text }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch (e) {
    console.warn('sendEmail: unreachable:', (e as Error).message);
    return { ok: false, reason: 'unreachable' };
  }

  const body = (await r.json().catch(() => null)) as {
    success?: boolean;
    errors?: { message?: string }[];
    result?: { permanent_bounces?: string[] };
  } | null;

  if (!r.ok || !body?.success) {
    const detail = body?.errors?.[0]?.message;
    console.warn(`sendEmail: rejected (HTTP ${r.status})`, detail ?? '');
    return { ok: false, reason: 'rejected', detail };
  }
  if (body.result?.permanent_bounces?.length) {
    return { ok: false, reason: 'bounced' };
  }
  return { ok: true };
}
