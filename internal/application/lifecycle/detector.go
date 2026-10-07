package lifecycle

import (
	"context"
	"sync"
	"time"

	"vpsmonitoring-agent/internal/application/metrics"
)

type processIdentity struct {
	PID       int64
	StartTime time.Time
}

type applicationState struct {
	AppID     int64
	HasState  bool
	Processes map[int64]processIdentity // keyed by PID
}

type Detector interface {
	Detect(ctx context.Context, currentMetrics []metrics.ApplicationProcessMetrics) []ApplicationProcessEvent
	Cleanup(ctx context.Context, activeAppIDs []int64)
}

type defaultDetector struct {
	mu     sync.Mutex
	states map[int64]*applicationState
}

func NewDetector() Detector {
	return &defaultDetector{
		states: make(map[int64]*applicationState),
	}
}

func ptrInt64(i int64) *int64        { return &i }
func ptrTime(t time.Time) *time.Time { return &t }

func (d *defaultDetector) Detect(ctx context.Context, currentMetrics []metrics.ApplicationProcessMetrics) []ApplicationProcessEvent {
	d.mu.Lock()
	defer d.mu.Unlock()

	var events []ApplicationProcessEvent

	for _, metric := range currentMetrics {
		// If matcher failed entirely (permissions), skip state change to prevent false disappearance.
		if metric.State == metrics.StateUnknown {
			continue
		}

		appID := metric.ApplicationID
		now := metric.CollectedAt

		// Build current identity map
		currentProcs := make(map[int64]processIdentity)
		for _, pid := range metric.PIDs {
			if st, ok := metric.ProcessStartTimes[pid]; ok {
				currentProcs[pid] = processIdentity{PID: pid, StartTime: st}
			}
		}

		state, ok := d.states[appID]
		if !ok || !state.HasState {
			// Initial observation
			newState := &applicationState{
				AppID:     appID,
				HasState:  true,
				Processes: currentProcs,
			}
			d.states[appID] = newState
			continue
		}

		prevProcs := state.Processes

		// Analyze disappeared
		for prevPID, prevIdent := range prevProcs {
			if currIdent, exists := currentProcs[prevPID]; !exists {
				// Process disappeared entirely
				// Is there a replacement? (We will detect replacement by new PIDs)
				// For now, emit a process_disappeared or restart_detected if a new one arrives.
				// Wait, if it disappears but a new one appears, it's a restart.
				// We can handle transitions precisely.

				// To keep events bounded and deduplicated:
				// If a PID disappears and no new PID appears, it's process_disappeared.
				// If it disappears and a new PID appears, we can emit restart_detected.

				// We'll process exact matches.
				// We'll track what disappeared and what appeared.
			} else if !currIdent.StartTime.Equal(prevIdent.StartTime) {
				// Same PID, different start time (PID reused)
				events = append(events, ApplicationProcessEvent{
					ApplicationID: appID,
					EventType:     EventProcessIdentityChanged,
					EventTime:     now,
					OldPID:        ptrInt64(prevPID),
					NewPID:        ptrInt64(currIdent.PID),
					OldStartTime:  ptrTime(prevIdent.StartTime),
					NewStartTime:  ptrTime(currIdent.StartTime),
					Details:       mustMarshalDetails(EventDetails{Reason: "pid_reused_new_start_time"}),
				})
			}
		}

		// Find disappeared and appeared (excluding reused PIDs handled above)
		var disappeared []processIdentity
		for prevPID, prevIdent := range prevProcs {
			if _, exists := currentProcs[prevPID]; !exists {
				disappeared = append(disappeared, prevIdent)
			}
		}

		var appeared []processIdentity
		for currPID, currIdent := range currentProcs {
			if _, exists := prevProcs[currPID]; !exists {
				appeared = append(appeared, currIdent)
			}
		}

		// Heuristic:
		// If 1 disappeared and 1 appeared -> restart_detected
		// If 0 disappeared and 1 appeared -> process_started
		// If 1 disappeared and 0 appeared -> process_disappeared
		// If multiple... we emit individual events to remain precise.

		for len(disappeared) > 0 && len(appeared) > 0 {
			// Pair them up as restart_detected
			oldP := disappeared[0]
			newP := appeared[0]

			disappeared = disappeared[1:]
			appeared = appeared[1:]

			events = append(events, ApplicationProcessEvent{
				ApplicationID: appID,
				EventType:     EventRestartDetected,
				EventTime:     now,
				OldPID:        ptrInt64(oldP.PID),
				NewPID:        ptrInt64(newP.PID),
				OldStartTime:  ptrTime(oldP.StartTime),
				NewStartTime:  ptrTime(newP.StartTime),
				Details:       mustMarshalDetails(EventDetails{Reason: "process_replaced"}),
			})
		}

		// Remaining disappeared
		for _, oldP := range disappeared {
			events = append(events, ApplicationProcessEvent{
				ApplicationID: appID,
				EventType:     EventProcessDisappeared,
				EventTime:     now,
				OldPID:        ptrInt64(oldP.PID),
				OldStartTime:  ptrTime(oldP.StartTime),
				Details:       mustMarshalDetails(EventDetails{Reason: "process_disappeared"}),
			})
		}

		// Remaining appeared
		for _, newP := range appeared {
			events = append(events, ApplicationProcessEvent{
				ApplicationID: appID,
				EventType:     EventProcessStarted,
				EventTime:     now,
				NewPID:        ptrInt64(newP.PID),
				NewStartTime:  ptrTime(newP.StartTime),
				Details:       mustMarshalDetails(EventDetails{Reason: "process_started"}),
			})
		}

		// Save current state for next cycle
		d.states[appID] = &applicationState{
			AppID:     appID,
			HasState:  true,
			Processes: currentProcs,
		}
	}

	return events
}

// Cleanup removes state for applications that are no longer active in the configuration.
func (d *defaultDetector) Cleanup(ctx context.Context, activeAppIDs []int64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	activeMap := make(map[int64]bool)
	for _, id := range activeAppIDs {
		activeMap[id] = true
	}

	for appID := range d.states {
		if !activeMap[appID] {
			delete(d.states, appID)
		}
	}
}
