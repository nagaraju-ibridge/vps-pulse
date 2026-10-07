package models

import "time"

// ServiceSnapshot represents the status of a single systemd service.
type ServiceSnapshot struct {
	Name        string    `json:"name"`
	ActiveState string    `json:"active_state"`
	SubState    string    `json:"sub_state"`
	LoadState   string    `json:"load_state"`
	Description string    `json:"description"`
	CollectedAt time.Time `json:"collected_at"`
}

// ServicePayload represents the complete payload sent to the backend.
type ServicePayload struct {
	CollectedAt time.Time         `json:"collected_at"`
	Services    []ServiceSnapshot `json:"services"`
}
