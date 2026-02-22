-- Migration: Add User Organization for Shared Items
-- This allows users to organize shared projects and tracks into their personal folder structure
-- with custom ordering, independent of the owner's organization.

-- User-specific organization for shared projects
CREATE TABLE user_shared_project_organization (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    folder_id INTEGER,
    custom_order INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL,
    UNIQUE(user_id, project_id)
);

CREATE INDEX idx_user_shared_project_org_user ON user_shared_project_organization(user_id);
CREATE INDEX idx_user_shared_project_org_folder ON user_shared_project_organization(folder_id);
CREATE INDEX idx_user_shared_project_org_order ON user_shared_project_organization(custom_order);

-- User-specific organization for shared tracks
CREATE TABLE user_shared_track_organization (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    track_id INTEGER NOT NULL,
    folder_id INTEGER,
    custom_order INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (track_id) REFERENCES tracks(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL,
    UNIQUE(user_id, track_id)
);

CREATE INDEX idx_user_shared_track_org_user ON user_shared_track_organization(user_id);
CREATE INDEX idx_user_shared_track_org_folder ON user_shared_track_organization(folder_id);
CREATE INDEX idx_user_shared_track_org_order ON user_shared_track_organization(custom_order);

-- Add custom_order to owned projects for consistent ordering behavior
-- This allows users to reorder their own projects in addition to shared projects
ALTER TABLE projects ADD COLUMN custom_order INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_projects_custom_order ON projects(custom_order);
