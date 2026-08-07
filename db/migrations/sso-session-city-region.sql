-- Richer session location for the Devices pane. `country` (cf-ipcountry) has
-- always been there; city and region come from cf-ipcity / cf-region, which
-- Cloudflare only sends when the zone has the "Add visitor location headers"
-- managed transform enabled — cf-ipcountry alone ships with IP geolocation.
--
-- Both are nullable with no backfill, deliberately: location is captured once at
-- login and never refreshed, so existing sessions genuinely have no city/region
-- and there is nothing truthful to backfill them with. They keep displaying
-- country-only until the user signs in again, which the "city, country" ->
-- "region, country" -> "country" fallback handles without a special case.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS city text;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS region text;
