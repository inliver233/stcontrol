-- Invitation policy and consumption are node-owned. Keeping a Controller-side
-- invitation table would create a second authority and permit double use.
DROP TABLE IF EXISTS invitation_codes;
