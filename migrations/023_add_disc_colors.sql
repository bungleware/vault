-- Add disc color preferences to user_preferences table
ALTER TABLE user_preferences ADD COLUMN disc_colors TEXT; -- JSON array of hex colors
ALTER TABLE user_preferences ADD COLUMN color_spread INTEGER DEFAULT 50; -- 0-100
ALTER TABLE user_preferences ADD COLUMN gradient_spread INTEGER DEFAULT 40; -- 0-200
