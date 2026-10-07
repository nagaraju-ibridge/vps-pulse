package main

import (
	"fmt"
)

type ApplicationRequestStats struct {
	LogAvailable bool
}

type ApplicationTelemetryEntry struct {
	LogAvailable *bool
}

func main() {
	enabledConfigs := []int{1, 2}
	logByApp := map[int]ApplicationRequestStats{
		1: {LogAvailable: true},
		2: {LogAvailable: true},
	}

	var batch []ApplicationTelemetryEntry

	for _, cfg := range enabledConfigs {
		entry := ApplicationTelemetryEntry{}

		if ls, ok := logByApp[cfg]; ok {
			entry.LogAvailable = &ls.LogAvailable
		}
		batch = append(batch, entry)
	}

	for i, e := range batch {
		fmt.Printf("Config %d: LogAvailable = %v\n", i+1, *e.LogAvailable)
	}
}
