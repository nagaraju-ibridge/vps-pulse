package lifecycle

import (
	"encoding/json"
	"time"
)

type EventType string

const (
	EventProcessStarted         EventType = "process_started"
	EventProcessDisappeared     EventType = "process_disappeared"
	EventRestartDetected        EventType = "restart_detected"
	EventProcessIdentityChanged EventType = "process_identity_changed"
)

// ApplicationProcessEvent models a bounded, local restart/lifecycle event.
type ApplicationProcessEvent struct {
	ApplicationID int64           `json:"application_id"`
	EventType     EventType       `json:"event_type"`
	EventTime     time.Time       `json:"event_time"`
	OldPID        *int64          `json:"old_pid,omitempty"`
	NewPID        *int64          `json:"new_pid,omitempty"`
	OldStartTime  *time.Time      `json:"old_start_time,omitempty"`
	NewStartTime  *time.Time      `json:"new_start_time,omitempty"`
	Details       json.RawMessage `json:"details,omitempty"`
}

type EventDetails struct {
	Reason string `json:"reason"`
}

func mustMarshalDetails(d EventDetails) json.RawMessage {
	b, _ := json.Marshal(d)
	return b
}
