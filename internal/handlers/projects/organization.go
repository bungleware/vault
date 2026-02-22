package projects

import (
	"database/sql"
	"errors"
	"log"
	"log/slog"
	"net/http"

	"bungleware/vault/internal/apperr"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/handlers"
	"bungleware/vault/internal/handlers/shared"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
)

func (h *ProjectsHandler) MoveProject(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")

	req, err := httputil.DecodeJSON[handlers.MoveProjectRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	ctx := r.Context()

	projectByPublic, err := h.db.GetProjectByPublicIDNoFilter(ctx, publicID)
	if err := httputil.HandleDBError(err, "project not found", "failed to query project"); err != nil {
		return err
	}

	// Check if this is a shared project
	isOwner := projectByPublic.UserID == int64(userID)

	if !isOwner {
		_, err := h.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
			ProjectID: projectByPublic.ID,
			SharedTo:  int64(userID),
		})
		if err := httputil.HandleDBError(err, "project not found", "failed to verify access"); err != nil {
			return err
		}

		var folderID sql.NullInt64
		if req.FolderID != nil {
			count, err := h.db.CheckFolderExists(ctx, sqlc.CheckFolderExistsParams{
				ID:     *req.FolderID,
				UserID: int64(userID),
			})
			if err != nil {
				return apperr.NewInternal("failed to verify folder", err)
			}
			if count == 0 {
				return apperr.NewNotFound("folder not found")
			}
			folderID = sql.NullInt64{Int64: *req.FolderID, Valid: true}
		}

		customOrder := int64(0)
		var maxOrderResult interface{}
		if folderID.Valid {
			slog.Debug("[MoveProject] calculating max order for shared project in folder", "project_id", projectByPublic.ID, "folder_id", folderID.Int64)
			maxOrderResult, err = h.db.GetMaxOrderInFolder(ctx, sqlc.GetMaxOrderInFolderParams{
				UserID:   int64(userID),
				FolderID: folderID,
			})
		} else {
			slog.Debug("[MoveProject] calculating max order for shared project at root", "project_id", projectByPublic.ID)
			maxOrderResult, err = h.db.GetMaxOrderAtRoot(ctx, int64(userID))
		}
		if err == nil {
			if maxOrder, ok := maxOrderResult.(int64); ok {
				customOrder = maxOrder + 1
				slog.Debug("[MoveProject] calculated custom order for shared project", "project_id", projectByPublic.ID, "max_order", maxOrder, "custom_order", customOrder)
			} else {
				slog.Debug("[MoveProject] failed to cast max order result to int64", "value", maxOrderResult)
			}
		} else {
			slog.Debug("[MoveProject] error getting max order", "error", err)
		}

		_, err = h.db.UpsertSharedProjectOrganization(ctx, sqlc.UpsertSharedProjectOrganizationParams{
			UserID:      int64(userID),
			ProjectID:   projectByPublic.ID,
			FolderID:    folderID,
			CustomOrder: customOrder,
		})
		if err != nil {
			return apperr.NewInternal("failed to organize shared project", err)
		}

		w.Header().Set("Content-Type", "application/json")
		return httputil.OKResult(w, shared.ConvertProjectWithIsShared(
			service.ProjectRowToProject(projectByPublic),
			true,
		))
	}

	project, err := h.service.MoveProject(ctx, publicID, int64(userID), req.FolderID)
	if errors.Is(err, sql.ErrNoRows) {
		return apperr.NewNotFound("project not found")
	}
	if err != nil {
		if err.Error() == "folder not found" {
			return apperr.NewNotFound(err.Error())
		}
		return apperr.NewInternal("failed to move project", err)
	}

	w.Header().Set("Content-Type", "application/json")
	return httputil.OKResult(w, shared.ConvertProject(project))
}

func (h *ProjectsHandler) MoveProjectsToFolder(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	req, err := httputil.DecodeJSON[handlers.MoveProjectsToFolderRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	var projectsWithOrder []service.ProjectWithOrder
	if len(req.Projects) > 0 {
		projectsWithOrder = make([]service.ProjectWithOrder, len(req.Projects))
		for i, p := range req.Projects {
			projectsWithOrder[i] = service.ProjectWithOrder{
				ProjectID:   p.ProjectID,
				CustomOrder: p.CustomOrder,
			}
		}
	} else {
		if len(req.ProjectIDs) == 0 {
			return apperr.NewBadRequest("project_ids or projects cannot be empty")
		}
		// Backwards compatibility: use ProjectIDs with sequential order
		projectsWithOrder = make([]service.ProjectWithOrder, len(req.ProjectIDs))
		for i, id := range req.ProjectIDs {
			projectsWithOrder[i] = service.ProjectWithOrder{
				ProjectID:   id,
				CustomOrder: int64(i),
			}
		}
	}

	projects, err := h.service.MoveProjectsToFolderWithOrder(r.Context(), projectsWithOrder, int64(userID), req.FolderID)
	if err != nil {
		if err.Error() == "folder not found" {
			return apperr.NewNotFound(err.Error())
		}
		log.Printf("Error moving projects: %v", err)
		return apperr.NewInternal("failed to move projects", err)
	}

	w.Header().Set("Content-Type", "application/json")
	response := make([]shared.ProjectResponse, len(projects))
	for i, project := range projects {
		response[i] = shared.ConvertProject(project)
	}
	return httputil.OKResult(w, response)
}
