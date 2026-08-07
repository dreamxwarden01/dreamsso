// cf-ipcountry (2-char ISO) -> human label. T1 = Tor exit; null/XX/unknown -> Unknown.
export function fmtCountry(code) {
  if (!code || code === 'XX') return 'Unknown';
  if (code === 'T1') return 'Tor network';
  try {
    return new Intl.DisplayNames(undefined, { type: 'region' }).of(code) || code;
  } catch {
    return code;
  }
}

// Session location, most specific form available:
//   "Vancouver, Canada"  ->  "British Columbia, Canada"  ->  "Canada"
// City and region only arrive when Cloudflare's "Add visitor location headers"
// transform is on for the zone; cf-ipcountry comes with IP geolocation alone. So
// every step degrades on its own, and a country-only row looks exactly as it did
// before. Tor/unknown never gets a city glued to it — "Vancouver, Tor network"
// would be a nonsense pairing.
export function fmtLocation({ city, region, country } = {}) {
  const place = fmtCountry(country);
  if (place === 'Unknown' || place === 'Tor network') return place;
  const detail = (city || '').trim() || (region || '').trim();
  return detail ? `${detail}, ${place}` : place;
}

// Compact relative timestamps for org views ("just now", "5m ago", "3d ago").
export const fmtAgo = (iso) => {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};
