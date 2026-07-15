// Shared test helper: answer the "Stay signed in?" (KMSI) page that now precedes
// every code mint. Given the response from the terminal login POST (/login,
// /login/challenge, or /login/passkey), if it's the KMSI page (200), POST the
// answer to /login/stay and return the resulting 302; otherwise pass it through.
// The session cookie is set on the terminal POST (transient); choice='yes' also
// re-sets it as persistent on the /login/stay response.
export const FORM = {
  'content-type': 'application/x-www-form-urlencoded',
  origin: 'null',
  'sec-fetch-site': 'same-origin',
};

// Safe to call after ANY terminal login step: it only acts when the response is
// actually the KMSI page (detected by the /login/stay form, read from a clone so
// the caller can still read the body). Challenge pages, error re-renders, and
// 302s pass straight through.
export async function answerKmsi(sso, r, txn, csrf, { choice = 'no', cookie = null } = {}) {
  if (r.status !== 200) return r;
  let body;
  try {
    body = await r.clone().text();
  } catch {
    return r;
  }
  if (!body.includes('/login/stay')) return r;
  return fetch(sso + '/login/stay', {
    method: 'POST',
    redirect: 'manual',
    headers: { ...FORM, ...(cookie ? { cookie } : {}) },
    body: new URLSearchParams({ txn, csrf, choice }),
  });
}
