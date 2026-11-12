package cfprobe

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var ifacePartRE = regexp.MustCompile(`^[A-Za-z0-9_.:\-\*\?\[\]]+$`)

var errLegacyCredential = errors.New("legacy credential configuration: reinstall with -token (no shared-secret fallback)")

func defaultConfig() Config {
	return Config{
		CollectInterval: 0,
		ReportInterval:  defaultReportIntervalSec,
		ResetDay:        1,
		ConnectionMode:  connectionModeAuto,
		PingMode:        pingModeTCP,
		UA:              defaultUserAgent,
		ConfigMD5:       "none",
	}
}

func normalizeBinaryValue(raw string, def bool) (bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def, nil
	}
	switch raw {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("仅支持 0 或 1")
	}
}

func normalizeConnectionMode(raw string) (string, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "", connectionModeAuto, "wss", "websocket":
		return connectionModeAuto, nil
	case connectionModeHTTP, "post":
		return connectionModeHTTP, nil
	default:
		return "", fmt.Errorf("connection_mode 仅支持 auto 或 http")
	}
}

func normalizePingMode(raw string) (string, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "", pingModeTCP:
		return pingModeTCP, nil
	case pingModeICMP:
		return pingModeICMP, nil
	default:
		return "", fmt.Errorf("ping_mode 仅支持 tcp 或 icmp")
	}
}

// normalizeUserAgentValue 校验自定义 UA：必须是 header 安全的可打印 ASCII，且不能包含
// 引号或反斜杠（会破坏 config.conf 的 KEY="value" 格式）。非法值一律回退默认 UA。
// userAgentAllowedChars 与服务端 settings.js 的白名单保持一致：只允许在请求头、
// config.conf 的 KV 格式、安装命令的 shell/PowerShell 引号下都安全的字符。
const userAgentAllowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _.-/,:;()+=@#*?~"

func isValidUserAgent(value string) bool {
	if value == "" || len(value) > maxUserAgentLength {
		return false
	}
	for i := 0; i < len(value); i++ {
		if strings.IndexByte(userAgentAllowedChars, value[i]) < 0 {
			return false
		}
	}
	return true
}

func normalizeUserAgentValue(raw string) string {
	value := strings.TrimSpace(raw)
	if isValidUserAgent(value) {
		return value
	}
	return defaultUserAgent
}

func normalizeInterfaceList(raw string) (string, error) {
	parts := strings.Split(raw, ",")
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		if len(name) > 64 || !ifacePartRE.MatchString(name) {
			return "", fmt.Errorf("interface 参数非法: %q", name)
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	joined := strings.Join(out, ",")
	if len(joined) > 255 {
		return "", errors.New("interface 参数过长")
	}
	return joined, nil
}

func parseKVFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseKVReader(f)
}

func parseKVReader(reader io.Reader) (map[string]string, error) {
	values := map[string]string{}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"`)
		values[k] = v
	}
	return values, scanner.Err()
}

func readConfig(path string) (Config, error) {
	cfg := defaultConfig()
	f, err := openPrivateFile(path)
	if err != nil {
		return cfg, fmt.Errorf("private config rejected: %w; reinstall with -token if needed", err)
	}
	defer f.Close()
	values, err := parseKVReader(f)
	if err != nil {
		return cfg, err
	}

	cfg.ServerID = values["SERVER_ID"]
	cfg.WorkerURL = values["WORKER_URL"]
	cfg.Name = values["NAME"]
	cfg.CollectInterval = parseIntDefault(values["COLLECT_INTERVAL"], cfg.CollectInterval)
	cfg.ReportInterval = parseIntDefault(values["REPORT_INTERVAL"], cfg.ReportInterval)
	cfg.CTNode = values["CT_NODE"]
	cfg.CUNode = values["CU_NODE"]
	cfg.CMNode = values["CM_NODE"]
	cfg.BDNode = values["BD_NODE"]
	cfg.Node1 = values["NODE_1"]
	cfg.Node2 = values["NODE_2"]
	cfg.Node3 = values["NODE_3"]
	cfg.Node4 = values["NODE_4"]
	cfg.Interface, _ = normalizeInterfaceList(values["INTERFACE"])
	cfg.ResetDay = parseIntDefault(values["RESET_DAY"], cfg.ResetDay)
	cfg.ConnectionMode, _ = normalizeConnectionMode(values["CONNECTION_MODE"])
	cfg.PingMode, _ = normalizePingMode(values["PING_MODE"])
	cfg.UA = normalizeUserAgentValue(values["UA"])
	cfg.AutoUpdate = values["AUTO_UPDATE"] == "1"
	cfg.UpdateProxy = strings.TrimSpace(values["UPDATE_PROXY"])
	cfg.TerminalEnabled = values["TERMINAL_ENABLED"] == "1"
	cfg.NodeToken = values["NODE_TOKEN"]
	cfg.ConfigMD5 = values["CONFIG_MD5"]
	if cfg.ConfigMD5 == "" {
		cfg.ConfigMD5 = "none"
	}
	normalizeConfigIntervals(&cfg)
	if _, legacy := values["SECRET"]; legacy {
		return cfg, errLegacyCredential
	}
	if _, legacy := values["TERMINAL_TOKEN"]; legacy {
		return cfg, errLegacyCredential
	}
	if cfg.NodeToken != "" && !validNodeToken(cfg.NodeToken) {
		return cfg, errors.New("invalid NODE_TOKEN: reinstall with -token")
	}
	return cfg, nil
}

func writeConfig(path string, cfg Config) error {
	tmp, err := stageConfig(path, cfg)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	return os.Rename(tmp, path)
}

func stageConfig(path string, cfg Config) (string, error) {
	if err := ensurePrivateConfigDirectory(filepath.Dir(path)); err != nil {
		return "", err
	}
	if err := verifyPrivateParent(path); err != nil {
		return "", err
	}
	normalizeConfigIntervals(&cfg)
	var buf bytes.Buffer
	var valueErr error
	writeKV := func(k, v string) {
		if strings.ContainsAny(v, "\r\n\x00") {
			valueErr = errors.New("configuration values must not contain control lines")
			return
		}
		fmt.Fprintf(&buf, "%s=\"%s\"\n", k, strings.ReplaceAll(v, `"`, `\"`))
	}
	writeKV("SERVER_ID", cfg.ServerID)
	writeKV("WORKER_URL", cfg.WorkerURL)
	writeKV("NAME", cfg.Name)
	writeKV("COLLECT_INTERVAL", strconv.Itoa(cfg.CollectInterval))
	writeKV("REPORT_INTERVAL", strconv.Itoa(cfg.ReportInterval))
	writeKV("CT_NODE", cfg.CTNode)
	writeKV("CU_NODE", cfg.CUNode)
	writeKV("CM_NODE", cfg.CMNode)
	writeKV("BD_NODE", cfg.BDNode)
	writeKV("NODE_1", cfg.Node1)
	writeKV("NODE_2", cfg.Node2)
	writeKV("NODE_3", cfg.Node3)
	writeKV("NODE_4", cfg.Node4)
	writeKV("INTERFACE", cfg.Interface)
	writeKV("RESET_DAY", strconv.Itoa(cfg.ResetDay))
	writeKV("CONNECTION_MODE", cfg.ConnectionMode)
	writeKV("PING_MODE", cfg.PingMode)
	writeKV("UA", cfg.UA)
	if cfg.AutoUpdate {
		writeKV("AUTO_UPDATE", "1")
	} else {
		writeKV("AUTO_UPDATE", "0")
	}
	writeKV("UPDATE_PROXY", cfg.UpdateProxy)
	writeKV("TERMINAL_ENABLED", boolInt(cfg.TerminalEnabled))
	writeKV("NODE_TOKEN", cfg.NodeToken)
	if cfg.ConfigMD5 == "" {
		cfg.ConfigMD5 = "none"
	}
	writeKV("CONFIG_MD5", cfg.ConfigMD5)
	if valueErr != nil {
		return "", valueErr
	}

	// A fresh 0600 file avoids following or reusing a predictable stale temp file.
	f, err := createPrivateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	keep := false
	defer func() {
		if !keep {
			os.Remove(tmp)
		}
	}()
	if err := protectPrivateFile(f); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := verifyPrivateParent(path); err != nil {
		f.Close()
		return "", err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	if err := verifyPrivateParent(path); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	keep = true
	return tmp, nil
}

func validNodeToken(token string) bool {
	return len(token) == 64 && !strings.ContainsFunc(token, func(r rune) bool {
		return !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f')
	})
}

func validateNodeTokenInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("node token file must be regular and owner-only")
	}
	return nil
}

func readNodeTokenFile(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("node token file requires an absolute local path")
	}
	f, err := openPrivateFile(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65))
	if err != nil || !validNodeToken(string(data)) {
		return "", errors.New("node token must be exactly 64 lowercase hexadecimal characters")
	}
	return string(data), nil
}

func openPrivateFile(path string) (*os.File, error) {
	if err := verifyPrivateParent(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateFileInfo(before); err != nil {
		return nil, err
	}
	f, err := openNodeTokenFile(path)
	if err != nil {
		return nil, errors.New("cannot open private credential file")
	}
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) {
		f.Close()
		return nil, errors.New("credential file changed while opening")
	}
	if err := validatePrivateFileInfo(info); err != nil {
		f.Close()
		return nil, err
	}
	if err := verifyPrivateFile(f); err != nil {
		f.Close()
		return nil, err
	}
	if err := verifyPrivateParent(path); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func validateUnixPrivatePermissions(mode os.FileMode, uid, currentUID uint32, directory bool) error {
	if uid != currentUID && (!directory || uid != 0) {
		return errors.New("private credential path has an untrusted owner")
	}
	if directory {
		if mode.Perm()&0022 != 0 && !(uid == 0 && mode&os.ModeSticky != 0) {
			return errors.New("private credential parent is replaceable by another user")
		}
	} else if mode.Perm()&0077 != 0 {
		return errors.New("credential file must be owner-only")
	}
	return nil
}

func normalizeConfigIntervals(cfg *Config) {
	if cfg.CollectInterval < 0 {
		cfg.CollectInterval = 0
	}
	if cfg.ReportInterval < 1 {
		cfg.ReportInterval = defaultReportIntervalSec
	}
	if cfg.CollectInterval > 0 && cfg.ReportInterval < cfg.CollectInterval {
		cfg.ReportInterval = cfg.CollectInterval
	}
	if cfg.ResetDay < 0 || cfg.ResetDay > 31 {
		cfg.ResetDay = 1
	}
	if cfg.ConfigMD5 == "" {
		cfg.ConfigMD5 = "none"
	}
	if mode, err := normalizeConnectionMode(cfg.ConnectionMode); err == nil {
		cfg.ConnectionMode = mode
	} else {
		cfg.ConnectionMode = connectionModeAuto
	}
	if mode, err := normalizePingMode(cfg.PingMode); err == nil {
		cfg.PingMode = mode
	} else {
		cfg.PingMode = pingModeTCP
	}
	cfg.UA = normalizeUserAgentValue(cfg.UA)
	cfg.UpdateProxy = strings.TrimSpace(cfg.UpdateProxy)
}

func parseIntDefault(raw string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return def
	}
	return n
}

func parseTrafficCorrectionGB(raw string) (uint64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || f < 0 || f > maxTrafficCorrectionGB {
		return 0, fmt.Errorf("流量校正值非法: %s", raw)
	}
	return uint64(f * 1024 * 1024 * 1024), nil
}

func splitInterfaceSet(raw string) map[string]bool {
	out := map[string]bool{}
	if raw == "" {
		return out
	}
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out[part] = true
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
