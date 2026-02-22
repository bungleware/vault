-- Add color shift rotation preference to user_preferences table
ALTER TABLE user_preferences ADD COLUMN color_shift_rotation INTEGER DEFAULT 0; -- 0-2 for rotation offset
