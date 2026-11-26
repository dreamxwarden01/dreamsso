// Transactional email: inline fallbacks, one action, no remote assets or scripts.
// Validity is an approximate duration at send time, never an inbox-local clock
// or a fresh deadline on resend. Backend expiry remains exact and unchanged.
function esc(s: string): string {
  return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}
const FONT = 'Arial,Helvetica,sans-serif';
export interface EmailShellParams {
  siteName: string;
  title: string;
  preheader?: string;
  bodyHtml: string; // trusted fragments constructed below; values are escaped
  footerNote?: string;
}
export interface RenderedEmail { subject: string; html: string; text: string }

export function emailShell(p: EmailShellParams): string {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="x-apple-disable-message-reformatting"><meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark"><title>${esc(p.title)}</title>
<style>
@media (max-width:520px){.mail-card{padding:24px 20px!important}}
@media (prefers-color-scheme:dark){.mail-bg{background:#111827!important}.mail-card{background:#1f2937!important;border-color:#374151!important}.mail-text{color:#f3f4f6!important}.mail-muted{color:#c4cbd4!important}}
</style></head>
<body class="mail-bg" style="margin:0;padding:0;background:#f3f5f8;font-family:${FONT}">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;mso-hide:all;font-size:1px;line-height:1px">${esc(p.preheader || p.title)}${'&#847;&zwnj;&nbsp;'.repeat(20)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f3f5f8" class="mail-bg"><tr><td align="center" style="padding:24px 12px">
<!--[if mso]><table role="presentation" width="480" cellpadding="0" cellspacing="0" border="0"><tr><td><![endif]-->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:480px">
<tr><td class="mail-text" style="padding:0 4px 16px;font-family:${FONT};font-size:17px;line-height:24px;font-weight:700;color:#1f2937">${esc(p.siteName)}</td></tr>
<tr><td bgcolor="#ffffff" class="mail-card" style="background:#ffffff;border:1px solid #dfe3e8;border-radius:12px;padding:28px">
<h1 class="mail-text" style="margin:0 0 16px;font-family:${FONT};font-size:24px;line-height:1.3;font-weight:700;color:#111827">${esc(p.title)}</h1>
${p.bodyHtml}
</td></tr>
${p.footerNote ? `<tr><td class="mail-muted" style="padding:16px 4px 0;font-family:${FONT};font-size:13px;line-height:1.5;color:#5f6672">${esc(p.footerNote)}</td></tr>` : ''}
</table><!--[if mso]></td></tr></table><![endif]-->
</td></tr></table></body></html>`;
}
export const paragraph = (html: string) => `<p class="mail-text" style="margin:0 0 18px;font-family:${FONT};font-size:16px;line-height:1.5;color:#374151">${html}</p>`;
const quiet = (text: string) => `<p class="mail-muted" style="margin:18px 0 0;font-family:${FONT};font-size:13px;line-height:1.5;color:#5f6672">${esc(text)}</p>`;
export const button = (href: string, label: string) => `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:4px 0 0"><tr><td bgcolor="#1a73e8" style="background:#1a73e8;border-radius:8px;mso-padding-alt:13px 22px"><a href="${esc(href)}" style="display:inline-block;padding:13px 22px;font-family:${FONT};font-size:16px;line-height:20px;font-weight:700;color:#ffffff!important;text-decoration:none;border-radius:8px">${esc(label)}</a></td></tr></table>`;
export const codeBlock = (code: string) => `<p class="mail-text" style="margin:4px 0 0;font-family:Consolas,Menlo,monospace;font-size:30px;line-height:1.4;font-weight:700;letter-spacing:5px;color:#111827">${esc(code)}</p>`;

export function formatEmailValidity(expiresAt: string, sentAt = Date.now()): string {
  const deadline = Date.parse(expiresAt);
  if (!Number.isFinite(deadline) || !Number.isFinite(sentAt)) throw new Error('Invalid email expiry');
  const remaining = deadline - sentAt;
  if (remaining <= 0) return 'This link has expired.';
  if (remaining < 60_000) return 'Expires in less than a minute.';
  // Minute rounding absorbs only seconds of dispatch delay. Whole days are
  // used only near a day boundary, not to round away many remaining hours.
  const minutes = Math.ceil(remaining / 60_000);
  const days = Math.round(minutes / 1440);
  let duration: string;
  if (days >= 2 && Math.abs(minutes - days * 1440) <= 5) duration = `${days} days`;
  else if (minutes >= 120) duration = `${Math.floor(minutes / 60)} hours`;
  else if (minutes >= 60) {
    const extra = Math.floor((minutes - 60) / 5) * 5;
    duration = extra ? `1 hour ${extra} minutes` : '1 hour';
  } else duration = `${minutes} minute${minutes === 1 ? '' : 's'}`;
  return `Expires in about ${duration}.`;
}
function expiryLine(p: { expiresAt?: string; minutes?: number }): string {
  if (p.expiresAt !== undefined) return formatEmailValidity(p.expiresAt);
  const minutes = p.minutes ?? 30;
  if (!Number.isFinite(minutes) || minutes <= 0) throw new Error('Invalid email validity');
  return `Expires in ${minutes} minute${minutes === 1 ? '' : 's'}.`;
}
function textMail(site: string, title: string, parts: string[]): string {
  return `${site}\n${title}\n\n${parts.filter(Boolean).join('\n\n')}`;
}

export function renderRegistrationEmail(p: { siteName: string; link: string; minutes?: number; expiresAt?: string; origin?: 'admin' | 'public' }): RenderedEmail {
  const invited = p.origin === 'admin';
  const title = invited ? "You're invited" : 'Create your account';
  const lead = invited ? `An administrator has invited you to join ${p.siteName}.` : 'Choose a username and password to finish signing up.';
  const action = invited ? 'Accept invitation' : 'Create account';
  const footer = invited ? "If you weren't expecting this invitation, you can ignore this email." : "If you didn't start signing up, you can ignore this email.";
  const expiry = expiryLine(p);
  return {
    subject: invited ? `You're invited to join ${p.siteName}` : `Finish creating your ${p.siteName} account`,
    html: emailShell({ siteName:p.siteName, title, preheader:invited ? 'Accept your invitation and create your account.' : lead,
      bodyHtml:paragraph(esc(lead))+button(p.link,action)+quiet(expiry), footerNote:footer }),
    text:textMail(p.siteName,title,[lead,`${action}: ${p.link}`,expiry,footer]),
  };
}

export function renderOtpEmail(p: { siteName: string; code: string; minutes: number }): RenderedEmail {
  const title='Your verification code', lead='Enter this code to continue.', expiry=expiryLine(p);
  const footer="If you didn't request this code, review your account security.";
  return { subject:`${p.code} is your ${p.siteName} verification code`,
    html:emailShell({siteName:p.siteName,title,preheader:'Use this code to verify it’s you.',bodyHtml:paragraph(lead)+codeBlock(p.code)+quiet(expiry),footerNote:footer}),
    text:textMail(p.siteName,title,[lead,p.code,expiry,footer]) };
}

export function renderPasswordResetEmail(p: { siteName: string; username: string; link: string; minutes: number }): RenderedEmail {
  const title='Reset your password', lead=`We received a password reset request for ${p.username}.`;
  const expiry=expiryLine(p), footer="If you didn't request this, you can ignore this email. Your password won't change.";
  return {subject:`Reset your ${p.siteName} password`,
    html:emailShell({siteName:p.siteName,title,preheader:'Choose a new password for your account.',bodyHtml:paragraph(`We received a password reset request for <strong>${esc(p.username)}</strong>.`)+button(p.link,'Choose new password')+quiet(expiry),footerNote:footer}),
    text:textMail(p.siteName,title,[lead,`Choose new password: ${p.link}`,expiry,footer])};
}

export function renderPasswordChangedEmail(p: { siteName: string; username: string; portalUrl: string }): RenderedEmail {
  const title='Your password was changed', lead=`The password for ${p.username} was changed.`;
  const advice="If this wasn't you, secure your email and review your account.";
  const footer="If you can't sign in, contact your administrator.";
  const link=p.portalUrl+'/security';
  return {subject:`Your ${p.siteName} password was changed`,
    html:emailShell({siteName:p.siteName,title,preheader:'Review your account if you didn’t make this change.',bodyHtml:paragraph(`The password for <strong>${esc(p.username)}</strong> was changed.`)+paragraph(advice)+button(link,'Review account security'),footerNote:footer}),
    text:textMail(p.siteName,title,[lead,advice,`Review account security: ${link}`,footer])};
}

export function renderEmailVerifyEmail(p: { siteName: string; link: string; minutes?: number; expiresAt?: string; kind: 'change'|'confirm' }): RenderedEmail {
  const change=p.kind==='change',title=change?'Confirm your new email':'Verify your email';
  const lead=change?'Confirm this address to use it for your account.':'Confirm this address for your account.';
  const action=change?'Confirm new email':'Verify email';
  const footer=change?"If you didn't request this change, you can ignore this email. Nothing will change.":"If you didn't request this, you can ignore this email.";
  const expiry=expiryLine(p);
  return {subject:change?`Confirm your new ${p.siteName} email address`:`Verify your ${p.siteName} email address`,
    html:emailShell({siteName:p.siteName,title,preheader:lead,bodyHtml:paragraph(lead)+button(p.link,action)+quiet(expiry),footerNote:footer}),
    text:textMail(p.siteName,title,[lead,`${action}: ${p.link}`,expiry,footer])};
}

export function renderEmailChangedEmail(p: { siteName: string; username: string; newEmailMasked: string; portalUrl: string }): RenderedEmail {
  const title='Your email address was changed',lead=`The email for ${p.username} is now ${p.newEmailMasked}.`;
  const advice="If this wasn't you, review your account security.";
  const footer="If you can't sign in, contact your administrator.";
  const link=p.portalUrl+'/security';
  return {subject:`Your ${p.siteName} email address was changed`,
    html:emailShell({siteName:p.siteName,title,preheader:'Review your account if you didn’t make this change.',bodyHtml:paragraph(`The email for <strong>${esc(p.username)}</strong> is now <strong>${esc(p.newEmailMasked)}</strong>.`)+paragraph(advice)+button(link,'Review account security'),footerNote:footer}),
    text:textMail(p.siteName,title,[lead,advice,`Review account security: ${link}`,footer])};
}

export function renderTestEmail(p: { siteName: string }): RenderedEmail {
  const title='Email sending works',lead=`This test was sent from the ${p.siteName} admin console.`;
  return {subject:`${p.siteName} test email`,html:emailShell({siteName:p.siteName,title,preheader:'Your email configuration is working.',bodyHtml:paragraph(esc(lead))}),text:textMail(p.siteName,title,[lead])};
}
