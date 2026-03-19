package service

import (
	"context"
	"database/sql"

	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
)

// SharedProjectInFolder holds a shared project's data needed for the folder contents response.
type SharedProjectInFolder struct {
	Project          sqlc.Project
	Org              sqlc.UserSharedProjectOrganization
	SharedByUsername string
	AllowEditing     bool
	AllowDownloads   bool
}

// SharedTrackInFolder holds a shared track's data needed for the folder contents response.
type SharedTrackInFolder struct {
	Track           sqlc.Track
	Project         sqlc.Project
	Org             sqlc.UserSharedTrackOrganization
	SharedByUsername string
	CanDownload     bool
	Waveform        string
	DurationSeconds  float64
}

// FolderContents is the result of GetFolderContents.
type FolderContents struct {
	Folder         sqlc.Folder
	Subfolders     []sqlc.Folder
	OwnedProjects  []sqlc.ListProjectsInFolderRow
	SharedProjects []SharedProjectInFolder
	SharedTracks   []SharedTrackInFolder
}

type FoldersService interface {
	CreateFolder(ctx context.Context, userID int64, name string, parentID *int64) (sqlc.Folder, error)
	ListFoldersByUser(ctx context.Context, userID int64) ([]sqlc.Folder, error)
	ListFoldersByParent(ctx context.Context, userID, parentID int64) ([]sqlc.Folder, error)
	ListAllFoldersByUser(ctx context.Context, userID int64) ([]sqlc.Folder, error)
	GetFolder(ctx context.Context, id, userID int64) (sqlc.Folder, error)
	UpdateFolder(ctx context.Context, id, userID int64, name *string, parentID *int64) (sqlc.Folder, error)
	DeleteFolderRecursive(ctx context.Context, folderID, userID int64) error
	EmptyFolder(ctx context.Context, folderID, userID int64) error
	GetFolderContents(ctx context.Context, folderID, userID int64) (FolderContents, error)
}

type foldersService struct {
	db *db.DB
}

func NewFoldersService(database *db.DB) FoldersService {
	return &foldersService{db: database}
}

func (s *foldersService) CreateFolder(ctx context.Context, userID int64, name string, parentID *int64) (sqlc.Folder, error) {
	var dbParentID sql.NullInt64
	if parentID != nil {
		count, err := s.db.CheckFolderExists(ctx, sqlc.CheckFolderExistsParams{
			ID:     *parentID,
			UserID: userID,
		})
		if err != nil {
			return sqlc.Folder{}, err
		}
		if count == 0 {
			return sqlc.Folder{}, ErrNotFound
		}
		dbParentID = sql.NullInt64{Int64: *parentID, Valid: true}
	}

	var folderOrder int64
	if parentID != nil {
		count, err := s.db.CountSubfoldersInFolder(ctx, dbParentID)
		if err == nil {
			folderOrder = count
		}
	} else {
		folders, err := s.db.ListFoldersByUser(ctx, userID)
		if err == nil {
			folderOrder = int64(len(folders))
		}
	}

	return s.db.CreateFolder(ctx, sqlc.CreateFolderParams{
		UserID:      userID,
		ParentID:    dbParentID,
		Name:        name,
		FolderOrder: folderOrder,
	})
}

func (s *foldersService) ListFoldersByUser(ctx context.Context, userID int64) ([]sqlc.Folder, error) {
	return s.db.ListFoldersByUser(ctx, userID)
}

func (s *foldersService) ListFoldersByParent(ctx context.Context, userID, parentID int64) ([]sqlc.Folder, error) {
	return s.db.ListFoldersByParent(ctx, sqlc.ListFoldersByParentParams{
		UserID:   userID,
		ParentID: sql.NullInt64{Int64: parentID, Valid: true},
	})
}

func (s *foldersService) ListAllFoldersByUser(ctx context.Context, userID int64) ([]sqlc.Folder, error) {
	return s.db.ListAllFoldersByUser(ctx, userID)
}

func (s *foldersService) GetFolder(ctx context.Context, id, userID int64) (sqlc.Folder, error) {
	return s.db.GetFolder(ctx, sqlc.GetFolderParams{ID: id, UserID: userID})
}

func (s *foldersService) UpdateFolder(ctx context.Context, id, userID int64, name *string, parentID *int64) (sqlc.Folder, error) {
	current, err := s.db.GetFolder(ctx, sqlc.GetFolderParams{ID: id, UserID: userID})
	if err != nil {
		return sqlc.Folder{}, err
	}

	folderName := current.Name
	if name != nil {
		folderName = *name
	}

	dbParentID := current.ParentID
	if parentID != nil {
		if *parentID == 0 {
			dbParentID = sql.NullInt64{Valid: false}
		} else {
			count, err := s.db.CheckFolderExists(ctx, sqlc.CheckFolderExistsParams{
				ID:     *parentID,
				UserID: userID,
			})
			if err != nil {
				return sqlc.Folder{}, err
			}
			if count == 0 {
				return sqlc.Folder{}, ErrNotFound
			}
			if *parentID == id {
				return sqlc.Folder{}, ErrBadRequest
			}
			dbParentID = sql.NullInt64{Int64: *parentID, Valid: true}
		}
	}

	return s.db.UpdateFolder(ctx, sqlc.UpdateFolderParams{
		Name:        folderName,
		ParentID:    dbParentID,
		FolderOrder: current.FolderOrder,
		ID:          id,
		UserID:      userID,
	})
}

func (s *foldersService) DeleteFolderRecursive(ctx context.Context, folderID, userID int64) error {
	projects, err := s.db.ListProjectsInFolder(ctx, sqlc.ListProjectsInFolderParams{
		FolderID: sql.NullInt64{Int64: folderID, Valid: true},
		UserID:   userID,
	})
	if err != nil {
		return err
	}
	for _, project := range projects {
		_, err := s.db.UpdateProjectFolder(ctx, sqlc.UpdateProjectFolderParams{
			FolderID: sql.NullInt64{Valid: false},
			Column2:  nil,
			ID:       project.ID,
			UserID:   userID,
		})
		if err != nil {
			return err
		}
	}

	sharedOrgs, err := s.db.ListSharedProjectOrganizationsInFolder(ctx, sqlc.ListSharedProjectOrganizationsInFolderParams{
		UserID:   userID,
		FolderID: sql.NullInt64{Int64: folderID, Valid: true},
	})
	if err == nil {
		for _, org := range sharedOrgs {
			_, err := s.db.UpsertSharedProjectOrganization(ctx, sqlc.UpsertSharedProjectOrganizationParams{
				UserID:      userID,
				ProjectID:   org.ProjectID,
				FolderID:    sql.NullInt64{Valid: false},
				CustomOrder: org.CustomOrder,
			})
			if err != nil {
				return err
			}
		}
	}

	subfolders, err := s.db.ListFoldersByParent(ctx, sqlc.ListFoldersByParentParams{
		UserID:   userID,
		ParentID: sql.NullInt64{Int64: folderID, Valid: true},
	})
	if err != nil {
		return err
	}
	for _, subfolder := range subfolders {
		if err := s.DeleteFolderRecursive(ctx, subfolder.ID, userID); err != nil {
			return err
		}
	}

	return s.db.DeleteFolder(ctx, sqlc.DeleteFolderParams{ID: folderID, UserID: userID})
}

func (s *foldersService) EmptyFolder(ctx context.Context, folderID, userID int64) error {
	folder, err := s.db.GetFolder(ctx, sqlc.GetFolderParams{ID: folderID, UserID: userID})
	if err != nil {
		return err
	}

	targetParentID := folder.ParentID

	projects, err := s.db.ListProjectsInFolder(ctx, sqlc.ListProjectsInFolderParams{
		FolderID: sql.NullInt64{Int64: folderID, Valid: true},
		UserID:   userID,
	})
	if err != nil {
		return err
	}
	for _, project := range projects {
		_, err := s.db.UpdateProjectFolder(ctx, sqlc.UpdateProjectFolderParams{
			FolderID: targetParentID,
			Column2:  nil,
			ID:       project.ID,
			UserID:   userID,
		})
		if err != nil {
			return err
		}
	}

	sharedOrgs, err := s.db.ListSharedProjectOrganizationsInFolder(ctx, sqlc.ListSharedProjectOrganizationsInFolderParams{
		UserID:   userID,
		FolderID: sql.NullInt64{Int64: folderID, Valid: true},
	})
	if err == nil {
		for _, org := range sharedOrgs {
			_, err := s.db.UpsertSharedProjectOrganization(ctx, sqlc.UpsertSharedProjectOrganizationParams{
				UserID:      userID,
				ProjectID:   org.ProjectID,
				FolderID:    targetParentID,
				CustomOrder: org.CustomOrder,
			})
			if err != nil {
				return err
			}
		}
	}

	subfolders, err := s.db.ListFoldersByParent(ctx, sqlc.ListFoldersByParentParams{
		UserID:   userID,
		ParentID: sql.NullInt64{Int64: folderID, Valid: true},
	})
	if err != nil {
		return err
	}
	for _, subfolder := range subfolders {
		_, err := s.db.UpdateFolderParent(ctx, sqlc.UpdateFolderParentParams{
			ParentID: targetParentID,
			ID:       subfolder.ID,
			UserID:   userID,
		})
		if err != nil {
			return err
		}
	}

	return s.db.DeleteFolder(ctx, sqlc.DeleteFolderParams{ID: folderID, UserID: userID})
}

func (s *foldersService) GetFolderContents(ctx context.Context, folderID, userID int64) (FolderContents, error) {
	folder, err := s.db.GetFolder(ctx, sqlc.GetFolderParams{ID: folderID, UserID: userID})
	if err != nil {
		return FolderContents{}, err
	}

	subfolders, err := s.db.ListFoldersByParent(ctx, sqlc.ListFoldersByParentParams{
		UserID:   userID,
		ParentID: sql.NullInt64{Int64: folderID, Valid: true},
	})
	if err != nil {
		return FolderContents{}, err
	}

	ownedProjects, err := s.db.ListProjectsInFolder(ctx, sqlc.ListProjectsInFolderParams{
		FolderID: sql.NullInt64{Int64: folderID, Valid: true},
		UserID:   userID,
	})
	if err != nil {
		return FolderContents{}, err
	}

	sharedProjectOrgs, _ := s.db.ListSharedProjectOrganizationsInFolder(ctx, sqlc.ListSharedProjectOrganizationsInFolderParams{
		UserID:   userID,
		FolderID: sql.NullInt64{Int64: folderID, Valid: true},
	})

	sharedProjects := make([]SharedProjectInFolder, 0, len(sharedProjectOrgs))
	for _, org := range sharedProjectOrgs {
		project, err := s.db.Queries.GetProjectByID(ctx, org.ProjectID)
		if err != nil {
			continue
		}

		entry := SharedProjectInFolder{
			Project: project,
			Org:     org,
		}

		share, err := s.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
			ProjectID: project.ID,
			SharedTo:  userID,
		})
		if err == nil {
			sharedByUser, err := s.db.Queries.GetUserByID(ctx, share.SharedBy)
			if err == nil {
				entry.SharedByUsername = sharedByUser.Username
			}
			entry.AllowEditing = share.CanEdit
			entry.AllowDownloads = share.CanDownload
		}
		sharedProjects = append(sharedProjects, entry)
	}

	sharedTrackOrgs, _ := s.db.Queries.ListSharedTrackOrganizationsInFolder(ctx, sqlc.ListSharedTrackOrganizationsInFolderParams{
		UserID:   userID,
		FolderID: sql.NullInt64{Int64: folderID, Valid: true},
	})

	sharedTracks := make([]SharedTrackInFolder, 0, len(sharedTrackOrgs))
	for _, trackOrg := range sharedTrackOrgs {
		track, err := s.db.Queries.GetTrackByID(ctx, trackOrg.TrackID)
		if err != nil {
			continue
		}
		project, err := s.db.Queries.GetProjectByID(ctx, track.ProjectID)
		if err != nil {
			continue
		}

		shares, err := s.db.ListUsersTrackIsSharedWith(ctx, track.ID)
		if err != nil || len(shares) == 0 {
			continue
		}

		var shareRecord sqlc.UserTrackShare
		for _, share := range shares {
			if share.SharedTo == userID {
				shareRecord = share
				break
			}
		}

		sharedByUser, err := s.db.GetUserByID(ctx, shareRecord.SharedBy)
		if err != nil {
			continue
		}

		var waveform string
		var duration float64
		if track.ActiveVersionID.Valid {
			version, err := s.db.GetTrackVersion(ctx, track.ActiveVersionID.Int64)
			if err == nil && version.DurationSeconds.Valid {
				duration = version.DurationSeconds.Float64
				files, err := s.db.ListTrackFilesByVersion(ctx, track.ActiveVersionID.Int64)
				if err == nil {
					for _, file := range files {
						if file.Waveform.Valid && file.Waveform.String != "" {
							waveform = file.Waveform.String
							break
						}
					}
				}
			}
		}

		sharedTracks = append(sharedTracks, SharedTrackInFolder{
			Track:           track,
			Project:         project,
			Org:             trackOrg,
			SharedByUsername: sharedByUser.Username,
			CanDownload:     shareRecord.CanDownload,
			Waveform:        waveform,
			DurationSeconds: duration,
		})
	}

	return FolderContents{
		Folder:         folder,
		Subfolders:     subfolders,
		OwnedProjects:  ownedProjects,
		SharedProjects: sharedProjects,
		SharedTracks:   sharedTracks,
	}, nil
}
