package metrics

import (
	"context"
	"errors"
	"testing"
	"time"

	"vpsmonitoring-agent/internal/application/matcher"
)

type fakeOSProvider struct {
	TotalMem uint64
	CPUMap   map[int32]float64
	RSSMap   map[int32]uint64
	MemErr   error
	CPUErr   map[int32]error
	RSSErr   map[int32]error
}

type fakeCPUProcess struct {
	values []float64
	calls  int
}

func (p *fakeCPUProcess) PercentWithContext(context.Context, time.Duration) (float64, error) {
	value := p.values[p.calls]
	p.calls++
	return value, nil
}

func TestDefaultOSProvider_ReusesProcessForIntervalCPU(t *testing.T) {
	process := &fakeCPUProcess{values: []float64{0, 7.25}}
	factoryCalls := 0
	provider := &defaultOSProvider{
		processes: make(map[int32]cpuProcess),
		newProcess: func(context.Context, int32) (cpuProcess, error) {
			factoryCalls++
			return process, nil
		},
	}

	first, err := provider.ProcessCPU(context.Background(), 59146)
	if err != nil {
		t.Fatalf("first CPU sample failed: %v", err)
	}
	second, err := provider.ProcessCPU(context.Background(), 59146)
	if err != nil {
		t.Fatalf("second CPU sample failed: %v", err)
	}

	if first != 0 {
		t.Fatalf("expected initial baseline sample to be 0, got %f", first)
	}
	if second != 7.25 {
		t.Fatalf("expected interval CPU sample 7.25, got %f", second)
	}
	if factoryCalls != 1 {
		t.Fatalf("expected one process instance, created %d", factoryCalls)
	}
}

func (p *fakeOSProvider) TotalMemory(ctx context.Context) (uint64, error) {
	if p.MemErr != nil {
		return 0, p.MemErr
	}
	return p.TotalMem, nil
}

func (p *fakeOSProvider) ProcessCPU(ctx context.Context, pid int32) (float64, error) {
	if err, ok := p.CPUErr[pid]; ok && err != nil {
		return 0, err
	}
	return p.CPUMap[pid], nil
}

func (p *fakeOSProvider) ProcessRSS(ctx context.Context, pid int32) (uint64, error) {
	if err, ok := p.RSSErr[pid]; ok && err != nil {
		return 0, err
	}
	return p.RSSMap[pid], nil
}

func TestCollector_BasicAggregation(t *testing.T) {
	now := time.Now()

	provider := &fakeOSProvider{
		TotalMem: 1000,
		CPUMap: map[int32]float64{
			100: 10.5,
			101: 20.0,
		},
		RSSMap: map[int32]uint64{
			100: 100,
			101: 200,
		},
	}

	collector := NewCollectorWithProvider(provider)

	matches := []matcher.ApplicationProcessMatch{
		{
			ApplicationID: 1,
			State:         matcher.StateMatched,
			Processes: []matcher.ProcessMatchEvidence{
				{PID: 100, StartTime: &now},
				{PID: 101, StartTime: &now},
			},
		},
	}

	results := collector.Collect(context.Background(), matches)

	if len(results) != 1 {
		t.Fatalf("expected 1 result")
	}

	res := results[0]
	if res.ProcessCount != 2 {
		t.Errorf("expected 2 processes, got %d", res.ProcessCount)
	}
	if *res.CPUPercent != 30.5 {
		t.Errorf("expected CPU 30.5, got %f", *res.CPUPercent)
	}
	if *res.MemoryBytes != 300 {
		t.Errorf("expected Mem 300, got %d", *res.MemoryBytes)
	}
	// 300 / 1000 = 30%
	if *res.MemoryPercent != 30.0 {
		t.Errorf("expected Mem%% 30.0, got %f", *res.MemoryPercent)
	}
}

func TestCollector_ProcessDisappearance(t *testing.T) {
	now := time.Now()

	provider := &fakeOSProvider{
		TotalMem: 1000,
		CPUMap: map[int32]float64{
			100: 10.0,
		},
		RSSMap: map[int32]uint64{
			100: 100,
		},
		CPUErr: map[int32]error{
			101: errors.New("process not found"),
		},
		RSSErr: map[int32]error{
			101: errors.New("process not found"),
		},
	}

	collector := NewCollectorWithProvider(provider)

	matches := []matcher.ApplicationProcessMatch{
		{
			ApplicationID: 1,
			State:         matcher.StateMatched,
			Processes: []matcher.ProcessMatchEvidence{
				{PID: 100, StartTime: &now},
				{PID: 101, StartTime: &now}, // This process disappeared
			},
		},
	}

	results := collector.Collect(context.Background(), matches)
	if len(results) != 1 {
		t.Fatalf("expected 1 result")
	}

	res := results[0]
	if res.ProcessCount != 2 {
		t.Errorf("process count should remain 2 based on evidence, got %d", res.ProcessCount)
	}
	if *res.CPUPercent != 10.0 {
		t.Errorf("expected CPU 10.0, got %f", *res.CPUPercent)
	}
	if *res.MemoryBytes != 100 {
		t.Errorf("expected Mem 100, got %d", *res.MemoryBytes)
	}
	if len(res.Warnings) != 2 { // One for CPU, one for RSS
		t.Errorf("expected 2 warnings, got %d", len(res.Warnings))
	}
}

func TestCollector_UnknownSystemMem(t *testing.T) {
	now := time.Now()

	provider := &fakeOSProvider{
		MemErr: errors.New("no system memory info"),
		CPUMap: map[int32]float64{100: 10.0},
		RSSMap: map[int32]uint64{100: 100},
	}

	collector := NewCollectorWithProvider(provider)
	matches := []matcher.ApplicationProcessMatch{
		{
			ApplicationID: 1,
			State:         matcher.StateMatched,
			Processes:     []matcher.ProcessMatchEvidence{{PID: 100, StartTime: &now}},
		},
	}

	results := collector.Collect(context.Background(), matches)
	res := results[0]

	if res.MemoryPercent != nil {
		t.Errorf("expected nil memory percent due to missing system memory")
	}
	if *res.MemoryBytes != 100 {
		t.Errorf("expected Mem 100, got %d", *res.MemoryBytes)
	}
}

func TestCollector_NotMatchedSkipsCollection(t *testing.T) {
	collector := NewCollectorWithProvider(&fakeOSProvider{})

	matches := []matcher.ApplicationProcessMatch{
		{
			ApplicationID: 1,
			State:         matcher.StateNotMatched,
		},
	}

	results := collector.Collect(context.Background(), matches)
	res := results[0]

	if res.ProcessCount != 0 {
		t.Errorf("expected 0 process count")
	}
	if res.CPUPercent != nil {
		t.Errorf("expected nil CPU")
	}
}
