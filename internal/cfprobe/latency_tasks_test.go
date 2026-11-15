package cfprobe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLatencySchema9Config(t *testing.T) {
	a := Agent{cfg: defaultConfig(), paths: Paths{ConfigFile: t.TempDir() + "/config.conf"}, log: newLogger(false)}
	body := "collect_interval=0&report_interval=60&reset_day=1&schema_version=9&connection_mode=http&ping_mode=tcp&latency_tasks=" + url.QueryEscape(`[{"id":"p_one","target":"127.0.0.1:443","interval":5}]`)
	if err := a.applyRemoteConfigWithOptions([]byte(body), http.Header{}, true); err != nil {
		t.Fatal(err)
	}
}

func TestLatencyTaskDueIntervals(t *testing.T) {
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
	for _, count := range []int{9, 32} {
		cfg := defaultConfig()
		for i := 0; i < count; i++ {
			interval := 60
			if i == 0 {
				interval = 5
			}
			cfg.LatencyTasks = append(cfg.LatencyTasks, LatencyTask{ID: fmt.Sprintf("p_%d", i), Target: listener.Addr().String(), Interval: interval})
		}
		histories := map[string]*rollingProbeHistory{}
		now := time.Now()
		collectLatencyTasks(context.Background(), cfg, now, histories, newLogger(false))
		collectLatencyTasks(context.Background(), cfg, now.Add(4*time.Second), histories, newLogger(false))
		if len(histories["p_0"].samples) != 1 {
			t.Fatal("ran before interval")
		}
		collectLatencyTasks(context.Background(), cfg, now.Add(5*time.Second), histories, newLogger(false))
		if len(histories["p_0"].samples) != 2 || len(histories["p_1"].samples) != 1 {
			t.Fatal("per-task intervals not applied")
		}
		cfg.LatencyTasks = cfg.LatencyTasks[1:]
		collectLatencyTasks(context.Background(), cfg, now.Add(60*time.Second), histories, newLogger(false))
		if _, ok := histories["p_0"]; ok {
			t.Fatal("removed assignment still active")
		}
		if len(histories) != count-1 || len(histories["p_1"].samples) != 2 {
			t.Fatal("assigned tasks not collected")
		}
	}
}

func TestLatencyWorkerRoundTrip(t *testing.T) {
	file := os.Getenv("CFSM_LATENCY_CONFIG_FIXTURE")
	if file == "" {
		t.Skip("run through latency-tasks.test.js")
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
	if len(cfg.LatencyTasks) != 9 && len(cfg.LatencyTasks) != 32 {
		t.Fatal("expected 9 or 32 tasks")
	}
	restored, err := readConfig(a.paths.ConfigFile)
	if err != nil || encodeLatencyTasks(restored.LatencyTasks) != encodeLatencyTasks(cfg.LatencyTasks) {
		t.Fatal("task persistence lost interval or assignment", err)
	}
	a.probes.Extra = collectLatencyTasks(context.Background(), cfg, time.Now(), map[string]*rollingProbeHistory{}, a.log)
	metrics := a.buildMetrics(cfg, "1", NetBytes{}, 0, 0, 0, 0, DiskIOStats{})
	report, _, err := a.buildReportBodyForConfig(cfg, metrics, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("CFSM_LATENCY_REPORT_FIXTURE"), report, 0600); err != nil {
		t.Fatal(err)
	}
}
