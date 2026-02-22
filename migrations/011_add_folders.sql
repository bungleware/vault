-- Folders table for organizing projects
CREATE TABLE folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    parent_id INTEGER,
    name TEXT NOT NULL,
    folder_order INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE
);

CREATE INDEX idx_folders_user_id ON folders(user_id);
CREATE INDEX idx_folders_parent_id ON folders(parent_id);

-- Add folder_id and folder_added_at columns to projects table
ALTER TABLE projects ADD COLUMN folder_id INTEGER REFERENCES folders(id) ON DELETE SET NULL;
ALTER TABLE projects ADD COLUMN folder_added_at DATETIME;

CREATE INDEX idx_projects_folder_id ON projects(folder_id);
