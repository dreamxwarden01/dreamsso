-- Profile pictures: identities.avatar holds the current FILE NAME
-- ({sub}-{16 hex}.webp) of the processed image under data/avatars/. The random
-- suffix makes the URL capability-style and cache-immutable; a new upload gets
-- a new name and the old file is deleted.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS avatar text;
