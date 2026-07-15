// Email templates — the branded base layout now; per-flow templates (password
// reset, email OTP, verification) land with their flows. NOTHING is hardcoded:
// site name / links come from settings via the params. Email-client constraints:
// inline styles only, no external images (text wordmark instead), <600px column.

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

export interface EmailShellParams {
  siteName: string;
  title: string;
  bodyHtml: string; // trusted fragments produced by the templates below
  footerNote?: string;
}

export function emailShell(p: EmailShellParams): string {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">
  <div style="display:none;max-height:0;overflow:hidden">${esc(p.title)}</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5;padding:32px 16px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px">
        <tr><td style="padding:0 4px 14px;font-size:16px;font-weight:700;color:#1f2937">${esc(p.siteName)}</td></tr>
        <tr><td style="background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;padding:28px 30px">
          <h1 style="margin:0 0 12px;font-size:19px;font-weight:600;color:#1f2937">${esc(p.title)}</h1>
          ${p.bodyHtml}
        </td></tr>
        <tr><td style="padding:16px 4px 0;font-size:12px;color:#9ca3af;line-height:1.5">
          ${p.footerNote ? esc(p.footerNote) + '<br>' : ''}Sent by ${esc(p.siteName)}. If you weren't expecting this email, you can safely ignore it.
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

// Shared fragment helpers for the per-flow templates.
export const paragraph = (html: string) =>
  `<p style="margin:0 0 14px;font-size:14px;line-height:1.6;color:#374151">${html}</p>`;
export const button = (href: string, label: string) =>
  `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:6px 0 10px"><tr><td style="background:#1a73e8;border-radius:9px">
     <a href="${esc(href)}" style="display:inline-block;padding:11px 22px;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none">${esc(label)}</a>
   </td></tr></table>`;
export const codeBlock = (code: string) =>
  `<p style="margin:6px 0 12px;font-size:26px;font-weight:700;letter-spacing:6px;color:#1f2937;font-family:ui-monospace,SFMono-Regular,Menlo,monospace">${esc(code)}</p>`;

// Sign-in verification code (the login challenge's email method).
export function renderOtpEmail(p: { siteName: string; code: string; minutes: number }): {
  subject: string;
  html: string;
  text: string;
} {
  return {
    subject: `${p.code} is your ${p.siteName} verification code`,
    html: emailShell({
      siteName: p.siteName,
      title: 'Your verification code',
      bodyHtml:
        paragraph('Use this code to finish signing in:') +
        codeBlock(p.code) +
        paragraph(`It expires in ${p.minutes} minutes. If you didn't try to sign in, you can ignore this email — your password still protects your account.`),
    }),
    text: `Your verification code\n\nUse this code to finish signing in: ${p.code}\n\nIt expires in ${p.minutes} minutes. If you didn't try to sign in, you can ignore this email.\n\nSent by ${p.siteName}.`,
  };
}

// Password reset link (requested from the account portal's /forgot page).
export function renderPasswordResetEmail(p: {
  siteName: string;
  username: string;
  link: string;
  minutes: number;
}): { subject: string; html: string; text: string } {
  return {
    subject: `Reset your ${p.siteName} password`,
    html: emailShell({
      siteName: p.siteName,
      title: 'Reset your password',
      bodyHtml:
        paragraph(`We received a request to reset the password for <strong>${esc(p.username)}</strong>.`) +
        button(p.link, 'Choose a new password') +
        paragraph(`This link works once and expires in ${p.minutes} minutes.`),
      footerNote: "If you didn't request this, you can ignore this email — your password won't change.",
    }),
    text: `Reset your password\n\nWe received a request to reset the password for ${p.username}. Open this link to choose a new one (works once, expires in ${p.minutes} minutes):\n\n${p.link}\n\nIf you didn't request this, you can ignore this email — your password won't change.\n\nSent by ${p.siteName}.`,
  };
}

// Post-reset notification — sent after the password actually changed.
export function renderPasswordChangedEmail(p: {
  siteName: string;
  username: string;
  portalUrl: string;
}): { subject: string; html: string; text: string } {
  return {
    subject: `Your ${p.siteName} password was changed`,
    html: emailShell({
      siteName: p.siteName,
      title: 'Your password was changed',
      bodyHtml:
        paragraph(
          `The password for <strong>${esc(p.username)}</strong> was just changed using a password reset link. ` +
          'All other sessions have been signed out.',
        ) +
        paragraph("If this was you, there's nothing else to do.") +
        paragraph("If this wasn't you, your email account may be compromised — secure it, then reset your password again and review your security settings.") +
        button(p.portalUrl + '/security', 'Review security settings'),
    }),
    text: `Your password was changed\n\nThe password for ${p.username} was just changed using a password reset link. All other sessions have been signed out.\n\nIf this was you, there's nothing else to do. If this wasn't you, your email account may be compromised — secure it, then reset your password again and review your security settings: ${p.portalUrl}/security\n\nSent by ${p.siteName}.`,
  };
}

// Registration link (requested from the account portal's /register/start page).
export function renderRegistrationEmail(p: {
  siteName: string;
  link: string;
  minutes: number;
}): { subject: string; html: string; text: string } {
  return {
    subject: `Finish creating your ${p.siteName} account`,
    html: emailShell({
      siteName: p.siteName,
      title: 'Finish creating your account',
      bodyHtml:
        paragraph(`You're almost there — open the link below to choose your username and password.`) +
        button(p.link, 'Create my account') +
        paragraph(`This link expires in ${p.minutes} minutes.`),
      footerNote: "If you didn't request this, you can ignore this email — no account was created.",
    }),
    text: `Finish creating your account\n\nOpen this link to choose your username and password (expires in ${p.minutes} minutes):\n\n${p.link}\n\nIf you didn't request this, you can ignore this email — no account was created.\n\nSent by ${p.siteName}.`,
  };
}

// Email verification link — kind 'change' goes to the NEW address (nothing
// swaps until it's clicked); kind 'confirm' verifies the CURRENT address.
export function renderEmailVerifyEmail(p: {
  siteName: string;
  link: string;
  minutes: number;
  kind: 'change' | 'confirm';
}): { subject: string; html: string; text: string } {
  const change = p.kind === 'change';
  const subject = change ? `Confirm your new ${p.siteName} email address` : `Verify your ${p.siteName} email address`;
  const lead = change
    ? 'Confirm this address to make it the email for your account. Your current email stays active until you do.'
    : 'Verify this address to finish setting up your account email.';
  return {
    subject,
    html: emailShell({
      siteName: p.siteName,
      title: change ? 'Confirm your new email' : 'Verify your email',
      bodyHtml:
        paragraph(lead) +
        button(p.link, change ? 'Confirm this address' : 'Verify this address') +
        paragraph(`This link works once and expires in ${p.minutes} minutes.`),
      footerNote: change
        ? "If you didn't request this change, you can ignore this email — nothing will change."
        : "If this wasn't you, you can ignore this email.",
    }),
    text: `${subject}\n\n${lead} Open this link (works once, expires in ${p.minutes} minutes):\n\n${p.link}\n\nIf you didn't request this, you can ignore this email.\n\nSent by ${p.siteName}.`,
  };
}

// Change notice to the OLD address — sent AFTER the new address is confirmed.
export function renderEmailChangedEmail(p: {
  siteName: string;
  username: string;
  newEmailMasked: string;
  portalUrl: string;
}): { subject: string; html: string; text: string } {
  return {
    subject: `Your ${p.siteName} email address was changed`,
    html: emailShell({
      siteName: p.siteName,
      title: 'Your email address was changed',
      bodyHtml:
        paragraph(
          `The email address for <strong>${esc(p.username)}</strong> was just changed to <strong>${esc(p.newEmailMasked)}</strong>. ` +
          'This address no longer receives sign-in codes or account notifications.',
        ) +
        paragraph("If this was you, there's nothing else to do.") +
        paragraph("If this wasn't you, reset your password immediately and review your security settings.") +
        button(p.portalUrl + '/forgot', 'Reset my password'),
    }),
    text: `Your email address was changed\n\nThe email address for ${p.username} was just changed to ${p.newEmailMasked}. This address no longer receives sign-in codes or account notifications.\n\nIf this was you, there's nothing else to do. If this wasn't you, reset your password immediately: ${p.portalUrl}/forgot\n\nSent by ${p.siteName}.`,
  };
}

// Test email — lets the admin panel verify the pipeline end to end.
export function renderTestEmail(p: { siteName: string }): { subject: string; html: string; text: string } {
  return {
    subject: `${p.siteName} — test email`,
    html: emailShell({
      siteName: p.siteName,
      title: 'Email sending works',
      bodyHtml: paragraph(
        `This is a test message from the <strong>${esc(p.siteName)}</strong> admin console. ` +
        'If you can read this, the outbound email configuration is working.',
      ),
    }),
    text: `Email sending works\n\nThis is a test message from the ${p.siteName} admin console. If you can read this, the outbound email configuration is working.\n\nSent by ${p.siteName}.`,
  };
}
