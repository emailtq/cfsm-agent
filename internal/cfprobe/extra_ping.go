package cfprobe

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxExtraPingBytes = 64 * 1024
const maxRemoteConfigBytes = 4*maxExtraPingBytes + 2048

var extraPingIDRE = regexp.MustCompile(`^p_[a-zA-Z0-9_-]{1,64}$`)
var extraPingHostRE = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)
var extraPingIPv4LikeRE = regexp.MustCompile(`^(?:[0-9]+\.){3}[0-9]+$`)

type ExtraPingNode struct {
	ID     string `json:"id"`
	Target string `json:"target"`
}

func (node *ExtraPingNode) UnmarshalJSON(data []byte) error {
	var input struct {
		ID     *string `json:"id"`
		Target *string `json:"target"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	if input.ID == nil || input.Target == nil {
		return errors.New("extra ping requires id and target")
	}
	node.ID, node.Target = *input.ID, *input.Target
	return nil
}

type extraProbeSnapshot struct {
	key    string
	result ProbeResult
}

type extraProbeMetric struct {
	Ping any `json:"ping"`
	Loss any `json:"loss"`
}

func decodeExtraPingNodes(raw string) ([]ExtraPingNode, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > maxExtraPingBytes {
		return nil, errors.New("extra ping configuration too large")
	}
	var nodes []ExtraPingNode
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&nodes); err != nil {
		return nil, errors.New("invalid extra ping configuration")
	}
	if nodes == nil {
		return nil, errors.New("extra ping configuration must be an array")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("invalid extra ping configuration tail")
	}
	seen := map[string]bool{}
	for _, node := range nodes {
		if !extraPingIDRE.MatchString(node.ID) || seen[node.ID] || !validExtraPingTarget(node.Target) {
			return nil, errors.New("invalid extra ping target or identity")
		}
		seen[node.ID] = true
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	return nodes, nil
}

func validExtraPingTarget(target string) bool {
	if target == "" {
		return true
	}
	if len(target) > 60 || strings.ContainsAny(target, " \t\r\n/@?#\\") || strings.Contains(target, "://") {
		return false
	}
	host, _, err := splitProbeTarget(target, defaultMetricsTCPPort)
	if err != nil {
		return false
	}
	if strings.ContainsAny(target, "[]") && (!strings.Contains(host, ":") || net.ParseIP(host) == nil) {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if extraPingIPv4LikeRE.MatchString(host) {
		for _, part := range strings.Split(host, ".") {
			number, err := strconv.Atoi(part)
			if err != nil || number < 0 || number > 255 {
				return false
			}
		}
		return true
	}
	if len(host) > 50 || !extraPingHostRE.MatchString(host) || strings.Contains(host, "..") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

func encodeExtraPingNodes(nodes []ExtraPingNode) string {
	if nodes == nil {
		nodes = []ExtraPingNode{}
	}
	data, _ := json.Marshal(nodes)
	return url.QueryEscape(string(data))
}

func equalExtraPingNodes(a, b []ExtraPingNode) bool {
	return encodeExtraPingNodes(a) == encodeExtraPingNodes(b)
}

// One sequential worker shares the existing rolling window; no goroutine per target.
func collectExtraPing(ctx context.Context, cfg Config, now time.Time, histories map[string]*rollingProbeHistory, log logger) map[string]extraProbeSnapshot {
	snap := map[string]extraProbeSnapshot{}
	active := map[string]bool{}
	for _, node := range cfg.ExtraPingNodes {
		if ctx.Err() != nil {
			break
		}
		active[node.ID] = true
		history := histories[node.ID]
		if history == nil {
			history = &rollingProbeHistory{}
			histories[node.ID] = history
		}
		key := probeHistoryKey(cfg.PingMode, node.Target)
		history.add(now, key, measureProbe(cfg.PingMode, node.Target, metricsProbeSampleCount, defaultMetricsTCPPort, log))
		snap[node.ID] = extraProbeSnapshot{key: key, result: history.snapshot(now)}
	}
	for id := range histories {
		if !active[id] {
			delete(histories, id)
		}
	}
	return snap
}

func extraProbeMetrics(cfg Config, probes map[string]extraProbeSnapshot) map[string]extraProbeMetric {
	metrics := map[string]extraProbeMetric{}
	if cfg.LatencyTasks != nil {
		cfg.ExtraPingNodes = nil
		for _, task := range cfg.LatencyTasks {
			cfg.ExtraPingNodes = append(cfg.ExtraPingNodes, ExtraPingNode{ID: task.ID, Target: task.Target})
		}
	}
	for _, node := range cfg.ExtraPingNodes {
		if node.Target == "" {
			metrics[node.ID] = extraProbeMetric{Ping: false, Loss: false}
			continue
		}
		snapshot, ok := probes[node.ID]
		if !ok || snapshot.key != probeHistoryKey(cfg.PingMode, node.Target) {
			metrics[node.ID] = extraProbeMetric{}
			continue
		}
		metrics[node.ID] = extraProbeMetric{Ping: probeRTTValue(node.Target, snapshot.result), Loss: probeLossValue(node.Target, snapshot.result)}
	}
	return metrics
}

func extraPingConfigFromFile(raw string) ([]ExtraPingNode, error) {
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return nil, err
	}
	return decodeExtraPingNodes(decoded)
}

func validateExtraPingEncoding(nodes []ExtraPingNode) error {
	data, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	if nodes == nil {
		data = []byte("[]")
	}
	_, err = decodeExtraPingNodes(string(data))
	return err
}
