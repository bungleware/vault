package handlers

import (
	"database/sql"
	"log/slog"
	"net/http"

	"bungleware/vault/internal/apperr"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
)

type OrganizationHandler struct {
	svc service.OrganizationService
}

func NewOrganizationHandler(svc service.OrganizationService) *OrganizationHandler {
	return &OrganizationHandler{svc: svc}
}

func convertSharedProjectOrganization(org sqlc.UserSharedProjectOrganization) SharedProjectOrganization {
	var folderID *int64
	if org.FolderID.Valid {
		folderID = &org.FolderID.Int64
	}

	createdAt := ""
	if org.CreatedAt.Valid {
		createdAt = org.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
	}

	updatedAt := ""
	if org.UpdatedAt.Valid {
		updatedAt = org.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
	}

	return SharedProjectOrganization{
		ID:          org.ID,
		UserID:      org.UserID,
		ProjectID:   org.ProjectID,
		FolderID:    folderID,
		CustomOrder: org.CustomOrder,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
}

func convertSharedTrackOrganization(org sqlc.UserSharedTrackOrganization) SharedTrackOrganization {
	var folderID *int64
	if org.FolderID.Valid {
		folderID = &org.FolderID.Int64
	}

	createdAt := ""
	if org.CreatedAt.Valid {
		createdAt = org.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
	}

	updatedAt := ""
	if org.UpdatedAt.Valid {
		updatedAt = org.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
	}

	return SharedTrackOrganization{
		ID:          org.ID,
		UserID:      org.UserID,
		TrackID:     org.TrackID,
		FolderID:    folderID,
		CustomOrder: org.CustomOrder,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
}

func (h *OrganizationHandler) OrganizeSharedProject(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	projectID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	req, err := httputil.DecodeJSON[OrganizeItemRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	_, err = h.svc.GetUserProjectShare(r.Context(), projectID, int64(userID))
	if err != nil {
		return apperr.NewNotFound("shared project not found or access denied")
	}

	var folderID sql.NullInt64
	if req.FolderID != nil {
		exists, err := h.svc.CheckFolderExists(r.Context(), *req.FolderID, int64(userID))
		if err != nil {
			return apperr.NewInternal("failed to verify folder", err)
		}
		if !exists {
			return apperr.NewNotFound("folder not found")
		}
		folderID = sql.NullInt64{Int64: *req.FolderID, Valid: true}
	}

	customOrder := int64(0)
	if req.CustomOrder != nil {
		customOrder = *req.CustomOrder
		slog.Debug("[OrganizeSharedProject] Using provided custom_order", "customOrder", customOrder, "projectID", projectID)
	} else {
		var maxOrder int64
		if folderID.Valid {
			slog.Debug("[OrganizeSharedProject] Calculating max order for project in folder", "projectID", projectID, "folderID", folderID.Int64)
			maxOrder, err = h.svc.GetMaxOrderInFolder(r.Context(), int64(userID), folderID.Int64)
		} else {
			slog.Debug("[OrganizeSharedProject] Calculating max order for project at root", "projectID", projectID)
			maxOrder, err = h.svc.GetMaxOrderAtRoot(r.Context(), int64(userID))
		}
		if err == nil {
			customOrder = maxOrder + 1
			slog.Debug("[OrganizeSharedProject] Calculated max_order and assigned custom_order", "maxOrder", maxOrder, "customOrder", customOrder, "projectID", projectID)
		} else {
			slog.Debug("[OrganizeSharedProject] Error getting max order", "error", err)
		}
	}

	slog.Debug("[OrganizeSharedProject] Upserting project", "projectID", projectID, "folderID", folderID, "customOrder", customOrder)
	org, err := h.svc.UpsertSharedProjectOrganization(r.Context(), sqlc.UpsertSharedProjectOrganizationParams{
		UserID:      int64(userID),
		ProjectID:   projectID,
		FolderID:    folderID,
		CustomOrder: customOrder,
	})
	if err != nil {
		slog.Debug("[OrganizeSharedProject] Error upserting", "error", err)
		return apperr.NewInternal("failed to organize project", err)
	}
	slog.Debug("[OrganizeSharedProject] Successfully organized project", "projectID", projectID, "customOrder", org.CustomOrder, "folderID", org.FolderID)

	return httputil.OKResult(w, convertSharedProjectOrganization(org))
}

func (h *OrganizationHandler) OrganizeSharedTrack(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	trackID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	req, err := httputil.DecodeJSON[OrganizeItemRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	_, err = h.svc.GetUserTrackShare(r.Context(), trackID, int64(userID))
	if err != nil {
		return apperr.NewNotFound("shared track not found or access denied")
	}

	var folderID sql.NullInt64
	if req.FolderID != nil {
		exists, err := h.svc.CheckFolderExists(r.Context(), *req.FolderID, int64(userID))
		if err != nil {
			return apperr.NewInternal("failed to verify folder", err)
		}
		if !exists {
			return apperr.NewNotFound("folder not found")
		}
		folderID = sql.NullInt64{Int64: *req.FolderID, Valid: true}
	}

	customOrder := int64(0)
	if req.CustomOrder != nil {
		customOrder = *req.CustomOrder
		slog.Debug("[OrganizeSharedTrack] Using provided custom_order", "customOrder", customOrder, "trackID", trackID)
	} else {
		var maxOrder int64
		if folderID.Valid {
			slog.Debug("[OrganizeSharedTrack] Calculating max order for track in folder", "trackID", trackID, "folderID", folderID.Int64)
			maxOrder, err = h.svc.GetMaxOrderInFolder(r.Context(), int64(userID), folderID.Int64)
		} else {
			slog.Debug("[OrganizeSharedTrack] Calculating max order for track at root", "trackID", trackID)
			maxOrder, err = h.svc.GetMaxOrderAtRoot(r.Context(), int64(userID))
		}
		if err == nil {
			customOrder = maxOrder + 1
			slog.Debug("[OrganizeSharedTrack] Calculated max_order and assigned custom_order", "maxOrder", maxOrder, "customOrder", customOrder, "trackID", trackID)
		} else {
			slog.Debug("[OrganizeSharedTrack] Error getting max order", "error", err)
		}
	}

	slog.Debug("[OrganizeSharedTrack] Upserting track", "trackID", trackID, "folderID", folderID, "customOrder", customOrder)
	org, err := h.svc.UpsertSharedTrackOrganization(r.Context(), sqlc.UpsertSharedTrackOrganizationParams{
		UserID:      int64(userID),
		TrackID:     trackID,
		FolderID:    folderID,
		CustomOrder: customOrder,
	})
	if err != nil {
		slog.Debug("[OrganizeSharedTrack] Error upserting", "error", err)
		return apperr.NewInternal("failed to organize track", err)
	}
	slog.Debug("[OrganizeSharedTrack] Successfully organized track", "trackID", trackID, "customOrder", org.CustomOrder, "folderID", org.FolderID)

	return httputil.OKResult(w, convertSharedTrackOrganization(org))
}

func (h *OrganizationHandler) BulkOrganize(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	req, err := httputil.DecodeJSON[BulkOrganizeRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	ctx := r.Context()

	for _, item := range req.Items {
		switch item.Type {
		case "project":
			if item.IsShared {
				var folderID sql.NullInt64
				if item.FolderID != nil {
					folderID = sql.NullInt64{Int64: *item.FolderID, Valid: true}
				}
				_, err := h.svc.UpsertSharedProjectOrganization(ctx, sqlc.UpsertSharedProjectOrganizationParams{
					UserID:      int64(userID),
					ProjectID:   item.ID,
					FolderID:    folderID,
					CustomOrder: item.CustomOrder,
				})
				if err != nil {
					return apperr.NewInternal("failed to organize shared project", err)
				}
			} else {
				err := h.svc.UpdateProjectCustomOrder(ctx, sqlc.UpdateProjectCustomOrderParams{
					CustomOrder: item.CustomOrder,
					ID:          item.ID,
					UserID:      int64(userID),
				})
				if err != nil {
					return apperr.NewInternal("failed to update project order", err)
				}
			}
		case "track":
			if item.IsShared {
				var folderID sql.NullInt64
				if item.FolderID != nil {
					folderID = sql.NullInt64{Int64: *item.FolderID, Valid: true}
				}
				_, err := h.svc.UpsertSharedTrackOrganization(ctx, sqlc.UpsertSharedTrackOrganizationParams{
					UserID:      int64(userID),
					TrackID:     item.ID,
					FolderID:    folderID,
					CustomOrder: item.CustomOrder,
				})
				if err != nil {
					return apperr.NewInternal("failed to organize shared track", err)
				}
			}
		default:
			return apperr.NewBadRequest("invalid item type")
		}
	}

	return httputil.OKResult(w, map[string]bool{"success": true})
}
