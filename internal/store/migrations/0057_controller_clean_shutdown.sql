-- A Controller that stops on purpose records, while it still holds the leadership lock, that
-- it finished serving its generation. The next process may then continue that generation
-- instead of promoting a new one, so a planned restart does not fence every browser session
-- and activity lease. A crash, a lost lock or an explicit recovery leaves it unset.
ALTER TABLE controller_epochs
  ADD COLUMN IF NOT EXISTS clean_shutdown_at TIMESTAMPTZ;
