package cfprobe

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestUnlimitedPingRemoteSchema(t *testing.T) {
	// Go 1.27 testing.TempDir prefers GOTMPDIR; use TestMain's private Windows TEMP for credential fixtures.
	if runtime.GOOS == "windows" {
		t.Setenv("GOTMPDIR", "")
	}
	tmp := t.TempDir()
	a := Agent{cfg: defaultConfig(), paths: Paths{ConfigFile: tmp + "/config.conf"}, log: newLogger(false)}
	nodes := []string{}
	for i := 0; i < 24; i++ {
		nodes = append(nodes, fmt.Sprintf(`{"id":"p_%d","target":"127.0.0.1:12345"}`, i))
	}
	body := "collect_interval=0&report_interval=60&reset_day=1&schema_version=8&interface=&connection_mode=http&ping_mode=tcp&extra_ping_nodes=" + url.QueryEscape("["+strings.Join(nodes, ",")+"]")
	if err := a.applyRemoteConfig([]byte(body), http.Header{"X-Agent-Config-Md5": []string{strings.Repeat("b", 32)}}); err != nil {
		t.Fatalf("schema 8 with 24 extra targets: %v", err)
	}
	got, err := readConfig(a.paths.ConfigFile)
	if err != nil || !reflect.DeepEqual(got.ExtraPingNodes, a.cfg.ExtraPingNodes) || len(got.ExtraPingNodes) != 24 {
		t.Fatalf("persisted targets: %v", err)
	}
}

func TestUnlimitedPingLocalCollection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	for _, count := range []int{1, 24} {
		t.Run(fmt.Sprintf("eight_plus_%d", count), func(t *testing.T) {
			cfg := defaultConfig()
			target := listener.Addr().String()
			cfg.CTNode, cfg.CUNode, cfg.CMNode, cfg.BDNode = target, target, target, target
			cfg.Node1, cfg.Node2, cfg.Node3, cfg.Node4 = target, target, target, target
			for i := 0; i < count; i++ {
				cfg.ExtraPingNodes = append(cfg.ExtraPingNodes, ExtraPingNode{ID: fmt.Sprintf("p_%d", i), Target: listener.Addr().String()})
			}
			histories := map[string]*rollingProbeHistory{}
			now := time.Now()
			snapshot := collectExtraPing(context.Background(), cfg, now, histories, newLogger(false))
			probes := localLegacyProbes(cfg, newLogger(false))
			probes.Extra = snapshot
			a := Agent{cfg: cfg, probes: probes}
			metrics := a.buildMetrics(cfg, "1", NetBytes{}, 0, 0, 0, 0, DiskIOStats{})
			body, _, err := a.buildReportBody(metrics, now)
			if err != nil {
				t.Fatal(err)
			}
			var report struct {
				Metrics struct {
					Extra map[string]extraProbeMetric `json:"extra_probes"`
				} `json:"metrics"`
			}
			if err := json.Unmarshal(body, &report); err != nil || len(report.Metrics.Extra) != count {
				t.Fatalf("actual serialized report count: %v", err)
			}
			for id, probe := range report.Metrics.Extra {
				if probe.Ping == nil || probe.Ping == "null" || probe.Loss != "0" {
					t.Fatalf("local probe %s failed: %+v", id, probe)
				}
			}
			var all struct {
				Metrics map[string]any `json:"metrics"`
			}
			if err := json.Unmarshal(body, &all); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"ping_ct", "ping_cu", "ping_cm", "ping_bd", "ping_node_1", "ping_node_2", "ping_node_3", "ping_node_4"} {
				if all.Metrics[field] == "null" || all.Metrics[field] == false || all.Metrics[field] == nil {
					t.Fatalf("legacy local probe %s missing", field)
				}
			}
			cfg.ExtraPingNodes = cfg.ExtraPingNodes[1:]
			collectExtraPing(context.Background(), cfg, now.Add(metricsProbeInterval), histories, newLogger(false))
			if _, exists := histories["p_0"]; exists {
				t.Fatal("removed identity retained")
			}
		})
	}
}

func localLegacyProbes(cfg Config, log logger) ProbeSnapshot {
	measure := func(target string) ProbeResult {
		return measureProbe(cfg.PingMode, target, metricsProbeSampleCount, defaultMetricsTCPPort, log)
	}
	return ProbeSnapshot{
		CT: measure(cfg.CTNode), CU: measure(cfg.CUNode), CM: measure(cfg.CMNode), BD: measure(cfg.BDNode),
		Node1: measure(cfg.Node1), Node2: measure(cfg.Node2), Node3: measure(cfg.Node3), Node4: measure(cfg.Node4),
	}
}

func TestUnlimitedPingDisabledFailureAndIdentity(t *testing.T) {
	if nodes, err := decodeExtraPingNodes(`[{"id":"p_ipv4","target":"001.002.003.004:80"}]`); err != nil || len(nodes) != 1 {
		t.Fatalf("Worker-accepted IPv4 notation rejected: %v", err)
	}
	for _, raw := range []string{`null`, `[{}]`, `[{"id":"p_0"}]`, `[{"id":"p_0","target":null}]`, `[{"id":"p_0","target":"a"},{"id":"p_0","target":"b"}]`, `[{"id":"p_0","target":"https://example.test"}]`, `[{"id":"p_0","target":"999.999.999.999"}]`, `[{"id":"p_0","target":"[127.0.0.1]"}]`, `[{"id":"p_0","target":"a","name":"not-in-protocol"}]`} {
		if _, err := decodeExtraPingNodes(raw); err == nil {
			t.Fatalf("accepted invalid config %s", raw)
		}
	}
	cfg := defaultConfig()
	cfg.ExtraPingNodes = []ExtraPingNode{{ID: "p_off"}, {ID: "p_fail", Target: "127.0.0.1:1"}}
	snap := collectExtraPing(context.Background(), cfg, time.Now(), map[string]*rollingProbeHistory{}, newLogger(false))
	metrics := extraProbeMetrics(cfg, snap)
	if metrics["p_off"].Ping != false || metrics["p_off"].Loss != false || metrics["p_fail"].Ping != "null" || metrics["p_fail"].Loss != "100" {
		t.Fatalf("sentinels %+v", metrics)
	}
	cfg.ExtraPingNodes[1].Target = "127.0.0.1:2"
	if extraProbeMetrics(cfg, snap)["p_fail"].Loss != nil {
		t.Fatal("old target result used for changed target")
	}
}

func TestUnlimitedPingStructuredWSSConfig(t *testing.T) {
	body, _, _ := wssConfigPayload(map[string]any{
		"collect_interval": 0, "report_interval": 60, "reset_day": 1, "schema_version": 8,
		"interface": "", "connection_mode": "http", "ping_mode": "tcp",
		"extra_ping_nodes": []any{map[string]any{"id": "p_wss", "target": "127.0.0.1:1"}},
	})
	values, err := url.ParseQuery(body)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := decodeExtraPingNodes(values.Get("extra_ping_nodes"))
	if err != nil || len(nodes) != 1 {
		t.Fatalf("structured WSS lost targets: %q (%v)", body, err)
	}
}

// The Worker regression provides its real serialized config and consumes this actual Agent report.
func TestUnlimitedPingWorkerRoundTrip(t *testing.T) {
	file := os.Getenv("CFSM_PING_CONFIG_FIXTURE")
	if file == "" {
		t.Skip("run through Worker unlimited-ping.test.js")
	}
	if runtime.GOOS == "windows" {
		t.Setenv("GOTMPDIR", "")
	}
	body, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	a := Agent{cfg: defaultConfig(), paths: Paths{ConfigFile: t.TempDir() + "/config.conf"}, log: newLogger(false)}
	if err := a.applyRemoteConfig(body, http.Header{"X-Agent-Config-Md5": []string{strings.Repeat("b", 32)}}); err != nil {
		t.Fatal(err)
	}
	cfg := a.configSnapshot()
	a.probes = localLegacyProbes(cfg, a.log)
	a.probes.Extra = collectExtraPing(context.Background(), cfg, time.Now(), map[string]*rollingProbeHistory{}, a.log)
	metrics := a.buildMetrics(cfg, "1", NetBytes{}, 0, 0, 0, 0, DiskIOStats{})
	report, _, err := a.buildReportBodyForConfig(cfg, metrics, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("CFSM_PING_REPORT_FIXTURE"), report, 0600); err != nil {
		t.Fatal(err)
	}
}
