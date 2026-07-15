// Parse a User-Agent into an accuracy-conscious label for the Devices pane.
// We deliberately show only the browser NAME + MAJOR version and the OS NAME
// (NO OS version): modern browsers freeze the UA platform token (Safari/Chrome
// pin macOS at "10_15_7", iOS lags), so the version is misleading. The user is on
// macOS 26 but the UA still says 10_15_7 — hence name-only. Result: "Chrome 149 on macOS".
export type DeviceType = 'desktop' | 'mobile' | 'tablet';

export interface DeviceInfo {
  name: string; // "Chrome 149 on macOS" — what the card shows
  browser: string; // "Chrome 149"
  os: string; // "macOS"
  type: DeviceType; // drives the leading icon
}

function parseOs(ua: string): string {
  if (/iPhone|iPod/.test(ua)) return 'iOS';
  if (/iPad/.test(ua)) return 'iPadOS';
  if (/Android/.test(ua)) return 'Android';
  if (/Windows NT/.test(ua)) return 'Windows';
  if (/Mac OS X|Macintosh/.test(ua)) return 'macOS';
  if (/CrOS/.test(ua)) return 'ChromeOS';
  if (/Linux/.test(ua)) return 'Linux';
  return '';
}

// Order matters: Edge/Opera/Samsung/in-app browsers all carry a "Chrome" token, so
// they must be matched before the generic Chrome rule. Safari last (everything WebKit
// carries "Safari"). Returns "Name 149" or "Name" when no version is found.
function parseBrowser(ua: string): string {
  const tests: [RegExp, string][] = [
    [/Edg(?:iOS|A)?\/(\d+)/, 'Edge'],
    [/OPR\/(\d+)|Opera\/(\d+)/, 'Opera'],
    [/SamsungBrowser\/(\d+)/, 'Samsung Internet'],
    [/CriOS\/(\d+)/, 'Chrome'], // Chrome on iOS
    [/FxiOS\/(\d+)/, 'Firefox'], // Firefox on iOS
    [/Firefox\/(\d+)/, 'Firefox'],
    [/(?:Chrome|Chromium|HeadlessChrome)\/(\d+)/, 'Chrome'],
    [/Version\/(\d+)[\d.]*\s+(?:Mobile\/\S+\s+)?Safari/, 'Safari'],
  ];
  for (const [re, label] of tests) {
    const m = re.exec(ua);
    if (m) {
      const major = m.slice(1).find(Boolean);
      return major ? `${label} ${major}` : label;
    }
  }
  if (/Safari/.test(ua)) return 'Safari';
  return '';
}

function parseType(ua: string): DeviceType {
  if (/iPad|Tablet|(?:Android(?!.*Mobile))/.test(ua)) return 'tablet';
  if (/Mobile|iPhone|iPod|Android/.test(ua)) return 'mobile';
  return 'desktop';
}

export function parseDevice(ua: string | null | undefined): DeviceInfo {
  const s = ua ?? '';
  const os = parseOs(s);
  const browser = parseBrowser(s);
  const type = parseType(s);
  const name = browser && os ? `${browser} on ${os}` : browser || os || 'Unknown device';
  return { name, browser, os, type };
}
