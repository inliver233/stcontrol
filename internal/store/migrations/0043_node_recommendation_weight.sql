-- Round 20: administrators can adjust the registration recommendation
-- weight per node.  A higher weight makes a node more likely to be
-- recommended for new registrations; 0 is neutral (default).
ALTER TABLE nodes
  ADD COLUMN IF NOT EXISTS recommendation_weight INT NOT NULL DEFAULT 0
    CHECK (recommendation_weight >= 0 AND recommendation_weight <= 100);
