package tracks

import (
	"net/http"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
)

type UpdateTrackOrderRequest struct {
	TrackOrders []struct {
		ID    int64 `json:"id"`
		Order int64 `json:"order"`
	} `json:"track_orders"`
}

func (h *TracksHandler) UpdateTracksOrder(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	req, err := httputil.DecodeJSON[UpdateTrackOrderRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if len(req.TrackOrders) == 0 {
		return httputil.NoContentResult(w)
	}

	orders := make([]service.TrackOrder, len(req.TrackOrders))
	for i, o := range req.TrackOrders {
		orders[i] = service.TrackOrder{ID: o.ID, Order: o.Order}
	}

	if err := h.tracks.UpdateTracksOrder(r.Context(), int64(userID), orders); err != nil {
		return mapServiceErr(err)
	}

	return httputil.NoContentResult(w)
}

func (h *TracksHandler) DuplicateTrack(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")

	track, err := h.tracks.DuplicateTrack(r.Context(), int64(userID), publicID)
	if err != nil {
		return mapServiceErr(err)
	}

	return httputil.CreatedResult(w, convertTrack(track))
}
