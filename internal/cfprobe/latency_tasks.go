package cfprobe

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"
)

type LatencyTask struct {
	ID       string `json:"id"`
	Target   string `json:"target"`
	Interval int    `json:"interval"`
}

func decodeLatencyTasks(raw string) ([]LatencyTask, error) {
	if raw == "" || raw == "null" {
		return nil, nil
	}
	if len(raw) > maxExtraPingBytes {
		return nil, errors.New("latency configuration too large")
	}
	var tasks []LatencyTask
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&tasks); err != nil {
		return nil, err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("invalid latency configuration tail")
	}
	seen := map[string]bool{}
	for _, task := range tasks {
		if !extraPingIDRE.MatchString(task.ID) || seen[task.ID] || task.Target == "" || !validExtraPingTarget(task.Target) || task.Interval < 5 || task.Interval > 3600 {
			return nil, errors.New("invalid latency task")
		}
		seen[task.ID] = true
	}
	return tasks, nil
}

func encodeLatencyTasks(tasks []LatencyTask) string {
	data, _ := json.Marshal(tasks)
	return url.QueryEscape(string(data))
}

// The existing single network worker runs due tasks; no goroutine per target.
func collectLatencyTasks(ctx context.Context, cfg Config, now time.Time, histories map[string]*rollingProbeHistory, log logger) map[string]extraProbeSnapshot {
	snap := map[string]extraProbeSnapshot{}
	active := map[string]bool{}
	for _, task := range cfg.LatencyTasks {
		if ctx.Err() != nil {
			break
		}
		active[task.ID] = true
		history := histories[task.ID]
		if history == nil {
			history = &rollingProbeHistory{}
			histories[task.ID] = history
		}
		key := probeHistoryKey(cfg.PingMode, task.Target)
		if history.target != key || len(history.samples) == 0 || now.Sub(history.samples[len(history.samples)-1].at) >= time.Duration(task.Interval)*time.Second {
			history.add(now, key, measureProbe(cfg.PingMode, task.Target, metricsProbeSampleCount, defaultMetricsTCPPort, log))
		}
		if len(history.samples) > 0 {
			snap[task.ID] = extraProbeSnapshot{key: key, result: history.snapshot(history.samples[len(history.samples)-1].at)}
		}
	}
	for id := range histories {
		if !active[id] {
			delete(histories, id)
		}
	}
	return snap
}
