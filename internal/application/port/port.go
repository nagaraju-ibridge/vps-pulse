package port

import (
	"time"
)

type PortState string

const (
	PortListening     PortState = "LISTENING"
	PortNotListening  PortState = "NOT_LISTENING"
	PortUnknown       PortState = "UNKNOWN"
	PortNotConfigured PortState = "NOT_CONFIGURED"
)

type ApplicationPortStatus struct {
	ApplicationID int64     `json:"application_id"`
	Port          int       `json:"port"`
	Configured    bool      `json:"configured"`
	State         PortState `json:"state"`
	CollectedAt   time.Time `json:"collected_at"`
	Warning       string    `json:"warning,omitempty"`
}
