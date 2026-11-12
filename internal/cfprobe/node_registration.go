package cfprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

func validateReportEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "/update" {
		return nil, errors.New("report endpoint must be a credential-free HTTPS URL ending in /update")
	}
	return u, nil
}

func sameOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 || len(via) == 0 || req.URL.Scheme != "https" || req.URL.User != nil || !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		return errors.New("refusing credential redirect outside HTTPS origin")
	}
	return nil
}

func registerNode(ctx context.Context, cfg Config, key string, client *http.Client) (Config, error) {
	u, err := validateReportEndpoint(cfg.WorkerURL)
	if err != nil {
		return cfg, err
	}
	nameUnits := 0
	for _, r := range cfg.Name {
		nameUnits++
		if r > 0xffff {
			nameUnits++
		}
	}
	if !validNodeToken(key) || !utf8.ValidString(cfg.Name) || nameUnits > 100 {
		return cfg, errors.New("invalid registration key or name")
	}
	u.Path = "/api/agent/register"
	u.RawPath = ""
	payload := map[string]string{}
	if cfg.Name != "" {
		payload["name"] = cfg.Name
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return cfg, errors.New("cannot create registration request")
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	guarded := *client
	guarded.CheckRedirect = sameOriginRedirect
	guarded.Timeout = 10 * time.Second
	resp, err := guarded.Do(req)
	if err != nil {
		return cfg, errors.New("node registration failed (HTTPS, TLS, redirect or network); existing installation unchanged")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return cfg, fmt.Errorf("node registration HTTP %d; existing installation unchanged", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(data) > 4096 {
		return cfg, errors.New("invalid registration response size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return cfg, errors.New("registration response must be an object")
	}
	fields := map[string]string{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || name != "serverId" && name != "token" {
			return cfg, errors.New("invalid registration response fields")
		}
		if _, duplicate := fields[name]; duplicate {
			return cfg, errors.New("duplicate registration response field")
		}
		value, err := decoder.Token()
		text, ok := value.(string)
		if err != nil || !ok {
			return cfg, errors.New("registration response fields must be strings")
		}
		fields[name] = text
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(fields) != 2 || !terminalIDRE.MatchString(fields["serverId"]) || !validNodeToken(fields["token"]) {
		return cfg, errors.New("invalid registration response schema")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return cfg, errors.New("invalid registration response trailing JSON")
	}
	cfg.ServerID, cfg.NodeToken = fields["serverId"], fields["token"]
	return cfg, nil
}

func prepareInstallCredentials(opts *InstallOptions, existing Config, existingErr error) error {
	if opts.RegisterKey != "" && (opts.NodeToken != "" || opts.Explicit["token"] || opts.Explicit["token_file"]) {
		return errors.New("node token and registration key are mutually exclusive")
	}
	if existingErr == nil || errors.Is(existingErr, errLegacyCredential) && (opts.Explicit["token"] || opts.Explicit["token_file"]) {
		flags := opts.Config
		opts.Config = existing
		mergeExplicitInstallConfig(&opts.Config, flags, opts.Explicit)
	} else if !errors.Is(existingErr, os.ErrNotExist) {
		if !(opts.Explicit["token"] || opts.Explicit["token_file"]) || !validNodeToken(opts.NodeToken) {
			return existingErr
		}
		// A rejected config is untrusted input: recover only from fresh explicit options.
		fresh := defaultConfig()
		mergeExplicitInstallConfig(&fresh, opts.Config, opts.Explicit)
		opts.Config = fresh
	}
	if _, err := validateReportEndpoint(opts.WorkerURL); err != nil {
		return err
	}
	if opts.TerminalEnabled && opts.Explicit["terminal"] && runtime.GOOS != "linux" {
		return errors.New("terminal is supported only on Linux")
	}
	if opts.RegisterKey != "" && !validNodeToken(opts.NodeToken) {
		cfg, err := registerNode(context.Background(), opts.Config, opts.RegisterKey, sharedReportHTTPClient(10*time.Second, usePublicDNSResolver(opts.Config)))
		if err != nil {
			return err
		}
		opts.Config = cfg
	}
	opts.RegisterKey = ""
	if !validNodeToken(opts.NodeToken) || opts.ServerID != "" && !terminalIDRE.MatchString(opts.ServerID) {
		return errors.New("valid NODE_TOKEN required: reinstall with -token/-token-file or -register-key and -url")
	}
	return nil
}
