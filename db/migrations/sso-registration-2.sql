-- Invitation retention rework (user design, 2026-07-08): voided/expired codes
-- linger VISIBLY for 24h before deletion instead of vanishing instantly.
--   clear_at: set at creation to expires_at + 24h; NULL on consumption
--             (permanent record); reset to now() + 24h on any void (org-page
--             void or overuse auto-void). The sweeper deletes past clear_at.
--   voided_at: distinguishes "Voided" from merely "Expired" in the UI.
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS voided_at timestamptz;
ALTER TABLE invitation_codes ADD COLUMN IF NOT EXISTS clear_at timestamptz;
UPDATE invitation_codes SET clear_at = expires_at + interval '24 hours'
 WHERE used_by IS NULL AND clear_at IS NULL;
