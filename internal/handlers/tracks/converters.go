package tracks

import (
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/handlers/shared"
	"bungleware/vault/internal/httputil"
)

func convertTrackListRows(rows []sqlc.ListTracksByProjectRow) []shared.TrackListResponse {
	result := make([]shared.TrackListResponse, len(rows))
	for i, row := range rows {
		result[i] = shared.TrackListResponse{
			TrackResponse: shared.TrackResponse{
				ID:                           row.ID,
				UserID:                       row.UserID,
				ProjectID:                    row.ProjectID,
				PublicID:                     row.PublicID,
				Title:                        row.Title,
				Artist:                       httputil.NullStringToPtr(row.Artist),
				Album:                        httputil.NullStringToPtr(row.Album),
				Key:                          httputil.NullStringToPtr(row.Key),
				Bpm:                          httputil.NullInt64ToPtr(row.Bpm),
				Notes:                        httputil.NullStringToPtr(row.Notes),
				NotesAuthorName:              httputil.NullStringToPtr(row.NotesAuthorName),
				NotesUpdatedAt:               httputil.FormatNullTime(row.NotesUpdatedAt),
				ActiveVersionID:              httputil.NullInt64ToPtr(row.ActiveVersionID),
				ActiveVersionDurationSeconds: httputil.NullFloat64ToPtr(row.ActiveVersionDurationSeconds),
				TrackOrder:                   row.TrackOrder,
				VisibilityStatus:             row.VisibilityStatus,
				CreatedAt:                    httputil.FormatNullTimeString(row.CreatedAt),
				UpdatedAt:                    httputil.FormatNullTimeString(row.UpdatedAt),
				Waveform:                     httputil.NullStringToPtr(row.Waveform),
				LossyTranscodingStatus:       httputil.NullStringToPtr(row.LossyTranscodingStatus),
			},
			ActiveVersionName: &row.ActiveVersionName,
			ProjectName:       &row.ProjectName,
			IsShared:          row.IsShared == 1,
		}
	}
	return result
}

func convertTrackListRowsFromUser(rows []sqlc.ListTracksByUserRow) []shared.TrackListResponse {
	result := make([]shared.TrackListResponse, len(rows))
	for i, row := range rows {
		result[i] = shared.TrackListResponse{
			TrackResponse: shared.TrackResponse{
				ID:                           row.ID,
				UserID:                       row.UserID,
				ProjectID:                    row.ProjectID,
				PublicID:                     row.PublicID,
				Title:                        row.Title,
				Artist:                       httputil.NullStringToPtr(row.Artist),
				Album:                        httputil.NullStringToPtr(row.Album),
				Key:                          httputil.NullStringToPtr(row.Key),
				Bpm:                          httputil.NullInt64ToPtr(row.Bpm),
				Notes:                        httputil.NullStringToPtr(row.Notes),
				NotesAuthorName:              httputil.NullStringToPtr(row.NotesAuthorName),
				NotesUpdatedAt:               httputil.FormatNullTime(row.NotesUpdatedAt),
				ActiveVersionID:              httputil.NullInt64ToPtr(row.ActiveVersionID),
				ActiveVersionDurationSeconds: httputil.NullFloat64ToPtr(row.ActiveVersionDurationSeconds),
				TrackOrder:                   row.TrackOrder,
				VisibilityStatus:             row.VisibilityStatus,
				CreatedAt:                    httputil.FormatNullTimeString(row.CreatedAt),
				UpdatedAt:                    httputil.FormatNullTimeString(row.UpdatedAt),
				Waveform:                     httputil.NullStringToPtr(row.Waveform),
				LossyTranscodingStatus:       httputil.NullStringToPtr(row.LossyTranscodingStatus),
			},
			ActiveVersionName: &row.ActiveVersionName,
			ProjectName:       &row.ProjectName,
		}
	}
	return result
}

func convertTrack(track sqlc.Track) shared.TrackResponse {
	return shared.TrackResponse{
		ID:              track.ID,
		UserID:          track.UserID,
		ProjectID:       track.ProjectID,
		PublicID:        track.PublicID,
		Title:           track.Title,
		Artist:          httputil.NullStringToPtr(track.Artist),
		Album:           httputil.NullStringToPtr(track.Album),
		Key:             httputil.NullStringToPtr(track.Key),
		Bpm:             httputil.NullInt64ToPtr(track.Bpm),
		Notes:           httputil.NullStringToPtr(track.Notes),
		NotesAuthorName: httputil.NullStringToPtr(track.NotesAuthorName),
		NotesUpdatedAt:  httputil.FormatNullTime(track.NotesUpdatedAt),
		ActiveVersionID: httputil.NullInt64ToPtr(track.ActiveVersionID),
		TrackOrder:      track.TrackOrder,
		CreatedAt:       httputil.FormatNullTimeString(track.CreatedAt),
		UpdatedAt:       httputil.FormatNullTimeString(track.UpdatedAt),
	}
}

func convertTrackWithDetails(row sqlc.GetTrackWithDetailsRow) shared.TrackListResponse {
	return shared.TrackListResponse{
		TrackResponse: shared.TrackResponse{
			ID:                           row.ID,
			UserID:                       row.UserID,
			ProjectID:                    row.ProjectID,
			PublicID:                     row.PublicID,
			Title:                        row.Title,
			Artist:                       httputil.NullStringToPtr(row.Artist),
			Album:                        httputil.NullStringToPtr(row.Album),
			Key:                          httputil.NullStringToPtr(row.Key),
			Bpm:                          httputil.NullInt64ToPtr(row.Bpm),
			ActiveVersionID:              httputil.NullInt64ToPtr(row.ActiveVersionID),
			ActiveVersionDurationSeconds: httputil.NullFloat64ToPtr(row.ActiveVersionDurationSeconds),
			TrackOrder:                   row.TrackOrder,
			VisibilityStatus:             row.VisibilityStatus,
			CreatedAt:                    httputil.FormatNullTimeString(row.CreatedAt),
			UpdatedAt:                    httputil.FormatNullTimeString(row.UpdatedAt),
			Waveform:                     httputil.NullStringToPtr(row.Waveform),
			LossyTranscodingStatus:       httputil.NullStringToPtr(row.LossyTranscodingStatus),
		},
		ActiveVersionName: &row.ActiveVersionName,
		ProjectName:       &row.ProjectName,
	}
}

func convertTracksWithDetails(rows []sqlc.ListTracksWithDetailsByProjectIDRow) []shared.TrackListResponse {
	return convertTracksWithDetailsWithPermissions(rows, 0, true, nil)
}

func convertSearchTracksRows(rows []sqlc.SearchTracksAccessibleByUserRow) []shared.TrackListResponse {
	result := make([]shared.TrackListResponse, len(rows))
	for i, row := range rows {
		result[i] = shared.TrackListResponse{
			TrackResponse: shared.TrackResponse{
				ID:                           row.ID,
				UserID:                       row.UserID,
				ProjectID:                    row.ProjectID,
				PublicID:                     row.PublicID,
				Title:                        row.Title,
				Artist:                       httputil.NullStringToPtr(row.Artist),
				Album:                        httputil.NullStringToPtr(row.Album),
				Key:                          httputil.NullStringToPtr(row.Key),
				Bpm:                          httputil.NullInt64ToPtr(row.Bpm),
				Notes:                        httputil.NullStringToPtr(row.Notes),
				NotesAuthorName:              httputil.NullStringToPtr(row.NotesAuthorName),
				NotesUpdatedAt:               httputil.FormatNullTime(row.NotesUpdatedAt),
				ActiveVersionID:              httputil.NullInt64ToPtr(row.ActiveVersionID),
				ActiveVersionDurationSeconds: httputil.NullFloat64ToPtr(row.ActiveVersionDurationSeconds),
				TrackOrder:                   row.TrackOrder,
				VisibilityStatus:             row.VisibilityStatus,
				CreatedAt:                    httputil.FormatNullTimeString(row.CreatedAt),
				UpdatedAt:                    httputil.FormatNullTimeString(row.UpdatedAt),
				Waveform:                     httputil.NullStringToPtr(row.Waveform),
				LossyTranscodingStatus:       httputil.NullStringToPtr(row.LossyTranscodingStatus),
			},
			ActiveVersionName: &row.ActiveVersionName,
			ProjectName:       &row.ProjectName,
			IsShared:          row.IsShared == 1,
		}
	}
	return result
}

func convertTracksWithDetailsWithPermissions(rows []sqlc.ListTracksWithDetailsByProjectIDRow, userID int64, isProjectOwner bool, projectShare *sqlc.UserProjectShare) []shared.TrackListResponse {
	result := make([]shared.TrackListResponse, len(rows))
	for i, row := range rows {
		var canEdit *bool
		var canDownload *bool

		if isProjectOwner {
			edit := true
			download := true
			canEdit = &edit
			canDownload = &download
		} else if projectShare != nil {
			canEdit = &projectShare.CanEdit
			canDownload = &projectShare.CanDownload
		}

		result[i] = shared.TrackListResponse{
			TrackResponse: shared.TrackResponse{
				ID:                           row.ID,
				UserID:                       row.UserID,
				ProjectID:                    row.ProjectID,
				PublicID:                     row.PublicID,
				Title:                        row.Title,
				Artist:                       httputil.NullStringToPtr(row.Artist),
				Album:                        httputil.NullStringToPtr(row.Album),
				Key:                          httputil.NullStringToPtr(row.Key),
				Bpm:                          httputil.NullInt64ToPtr(row.Bpm),
				Notes:                        httputil.NullStringToPtr(row.Notes),
				NotesAuthorName:              httputil.NullStringToPtr(row.NotesAuthorName),
				NotesUpdatedAt:               httputil.FormatNullTime(row.NotesUpdatedAt),
				ActiveVersionID:              httputil.NullInt64ToPtr(row.ActiveVersionID),
				ActiveVersionDurationSeconds: httputil.NullFloat64ToPtr(row.ActiveVersionDurationSeconds),
				TrackOrder:                   row.TrackOrder,
				VisibilityStatus:             row.VisibilityStatus,
				CreatedAt:                    httputil.FormatNullTimeString(row.CreatedAt),
				UpdatedAt:                    httputil.FormatNullTimeString(row.UpdatedAt),
				Waveform:                     httputil.NullStringToPtr(row.Waveform),
				LossyTranscodingStatus:       httputil.NullStringToPtr(row.LossyTranscodingStatus),
			},
			ActiveVersionName: &row.ActiveVersionName,
			ProjectName:       &row.ProjectName,
			IsShared:          row.IsShared == 1,
			CanEdit:           canEdit,
			CanDownload:       canDownload,
		}
	}
	return result
}
