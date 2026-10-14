import express, { type RequestHandler } from 'express';

export const EVENT_PATH = '/backchannel/events';
export const MAX_EVENT_TOKEN_BYTES = 262_144;
export const MAX_EVENT_FORM_BYTES = MAX_EVENT_TOKEN_BYTES + 1024;

/** Mounted before the ordinary 100 KiB parsers and after the first-run gate. */
export const eventForm: RequestHandler = (req, res, next) => {
  if (req.method !== 'POST') return next();
  if (!req.is('application/x-www-form-urlencoded')) {
    res.status(415).json({ error: 'unsupported_media_type' });return;
  }
  parseForm(req, res, error => {
    if (!error) return next();
    const status = typeof error.status === 'number' ? error.status : 400;
    res.status(status === 413 ? 413 : status === 415 ? 415 : 400).json({
      error: status === 413 ? 'event_form_too_large' : status === 415 ? 'unsupported_media_type' : 'invalid_event_form',
    });
  });
};
const parseForm = express.urlencoded({ extended: false, limit: MAX_EVENT_FORM_BYTES, parameterLimit: 1, inflate: false });

export function eventToken(body: unknown): string | null {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const values = body as Record<string, unknown>;
  if (Object.keys(values).length !== 1 || typeof values.event_token !== 'string') return null;
  const token = values.event_token;
  return Buffer.byteLength(token, 'utf8') <= MAX_EVENT_TOKEN_BYTES
    && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token) ? token : null;
}
