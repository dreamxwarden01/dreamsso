import type { Request, Response, NextFunction } from 'express';

// Baseline security headers for every response. HSTS is intentionally NOT set here
// — Cloudflare owns it at the edge (origin is CF-IP-locked). The per-page, nonce-based
// CSP is added alongside the HTML login UI in the next slice.
export function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('X-XSS-Protection', '0');
  next();
}
