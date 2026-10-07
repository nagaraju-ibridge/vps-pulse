package main

import (
	"encoding/json"
	"fmt"
)

type Stats struct {
	LogAvailable bool
}

type Entry struct {
	LogAvailable *bool `json:"log_available"`
}

func main() {
	logByApp := map[int]Stats{
		1: {LogAvailable: true},
		2: {LogAvailable: false},
	}

	var entries []Entry
	for _, id := range []int{1, 2} {
		var entry Entry
		if ls, ok := logByApp[id]; ok {
			entry.LogAvailable = &ls.LogAvailable
		}
		entries = append(entries, entry)
	}

	b, _ := json.Marshal(entries)
	fmt.Println(string(b))

	// Wait, is the map iteration ordered? No, range over slice is ordered.
}
