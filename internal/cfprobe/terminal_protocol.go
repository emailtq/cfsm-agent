package cfprobe

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"unicode/utf8"
)

const (
	terminalProtocolVersion      = 1
	terminalMaxSessions          = 4
	terminalMaxDataFrameBytes    = 16 * 1024
	terminalMaxControlFrameBytes = 4 * 1024
	terminalCreditBytes          = 256 * 1024
	terminalMaxDimension         = 500
	terminalMaxSafeInteger       = 9007199254740991
)

// Roles identify the sender, matching the Worker's V1 contract.
var terminalRoleTypes = map[string][]string{
	"agent-control":  {"hello", "disabled", "ping", "pong"},
	"broker-control": {"open", "close", "bound", "disable", "ping", "pong"},
	"browser":        {"resize", "ack", "ping", "pong"},
	"agent":          {"ready", "ack", "exit", "error", "ping", "pong"},
	"broker":         {"start", "ready", "resize", "ack", "exit", "error", "ping", "pong"},
}

var terminalControlFields = map[string][]string{
	"hello":    {"type", "protocol", "platform", "capabilities"},
	"open":     {"type", "protocol", "sessionId", "ticket", "cols", "rows"},
	"close":    {"type", "sessionId", "reason"},
	"bound":    {"type", "serverId", "connectionId", "generation", "credentialVersion"},
	"disable":  {"type", "operationId", "serverId", "connectionId", "generation", "credentialVersion"},
	"disabled": {"type", "operationId", "serverId", "connectionId", "generation", "credentialVersion"},
	"start":    {"type", "cols", "rows"},
	"resize":   {"type", "cols", "rows"},
	"ack":      {"type", "bytes"},
	"exit":     {"type", "code"},
	"error":    {"type", "code"},
	"ready":    {"type"}, "ping": {"type"}, "pong": {"type"},
}

var terminalIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var terminalCodeRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type terminalControl struct {
	Type                                string
	Protocol                            int
	Platform                            string
	Capabilities                        []string
	SessionID                           string
	Ticket                              string
	Cols, Rows                          int
	Bytes                               int64
	ExitCode                            int
	Code, Reason                        string
	ServerID, ConnectionID, OperationID string
	Generation, CredentialVersion       int64
}

func validateTerminalSize(cols, rows int) bool {
	return cols >= 1 && cols <= terminalMaxDimension && rows >= 1 && rows <= terminalMaxDimension
}

func parseTerminalControl(text []byte, role string) (terminalControl, error) {
	invalid := errors.New("invalid terminal control")
	var frame terminalControl
	if len(text) > terminalMaxControlFrameBytes || !utf8.Valid(text) {
		return frame, invalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(text, &fields) != nil || fields == nil {
		return frame, invalid
	}
	str := func(key string) string {
		var value string
		_ = json.Unmarshal(fields[key], &value)
		return value
	}
	frame.Type = str("type")
	allowed := false
	for _, kind := range terminalRoleTypes[role] {
		if frame.Type == kind {
			allowed = true
		}
	}
	expected := terminalControlFields[frame.Type]
	if !allowed || len(fields) != len(expected) {
		return terminalControl{}, invalid
	}
	for _, key := range expected {
		if _, ok := fields[key]; !ok {
			return terminalControl{}, invalid
		}
	}
	number := func(key string, min, max float64) (int64, bool) {
		var value float64
		if string(fields[key]) == "null" || json.Unmarshal(fields[key], &value) != nil || math.IsInf(value, 0) || value < min || value > max || math.Trunc(value) != value {
			return 0, false
		}
		return int64(value), true
	}
	size := func() bool {
		cols, colsOK := number("cols", 1, terminalMaxDimension)
		rows, rowsOK := number("rows", 1, terminalMaxDimension)
		frame.Cols, frame.Rows = int(cols), int(rows)
		return colsOK && rowsOK && validateTerminalSize(frame.Cols, frame.Rows)
	}
	valid := true
	switch frame.Type {
	case "hello":
		protocol, ok := number("protocol", 1, 1)
		frame.Protocol, frame.Platform = int(protocol), str("platform")
		valid = ok && frame.Platform == "linux" && json.Unmarshal(fields["capabilities"], &frame.Capabilities) == nil && (len(frame.Capabilities) == 1 || len(frame.Capabilities) == 2) && frame.Capabilities[0] == "terminal.pty.v1" && (len(frame.Capabilities) == 1 || frame.Capabilities[1] == "terminal.disable.v1")
	case "bound", "disable", "disabled":
		frame.ServerID, frame.ConnectionID, frame.OperationID = str("serverId"), str("connectionId"), str("operationId")
		generation, genOK := number("generation", 1, terminalMaxSafeInteger)
		version, verOK := number("credentialVersion", 1, terminalMaxSafeInteger)
		frame.Generation, frame.CredentialVersion = generation, version
		valid = genOK && verOK && terminalIDRE.MatchString(frame.ServerID) && terminalIDRE.MatchString(frame.ConnectionID) && (frame.Type == "bound" || terminalIDRE.MatchString(frame.OperationID))
	case "open":
		protocol, ok := number("protocol", 1, 1)
		frame.Protocol, frame.SessionID, frame.Ticket = int(protocol), str("sessionId"), str("ticket")
		valid = ok && terminalIDRE.MatchString(frame.SessionID) && validNodeToken(frame.Ticket) && size()
	case "close":
		frame.SessionID, frame.Reason = str("sessionId"), str("reason")
		valid = terminalIDRE.MatchString(frame.SessionID) && terminalCodeRE.MatchString(frame.Reason)
	case "start", "resize":
		valid = size()
	case "ack":
		frame.Bytes, valid = number("bytes", 0, terminalMaxSafeInteger)
	case "exit":
		code, ok := number("code", -1, 255)
		frame.ExitCode, valid = int(code), ok
	case "error":
		frame.Code = str("code")
		valid = terminalCodeRE.MatchString(frame.Code)
	}
	if !valid {
		return terminalControl{}, invalid
	}
	return frame, nil
}

func terminalWebSocketURL(reportURL, sessionID string) (string, error) {
	u, err := url.Parse(reportURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return "", errors.New("terminal requires a credential-free HTTPS reporting origin")
	}
	path := "/api/agent/terminal/control"
	if sessionID != "" {
		if !terminalIDRE.MatchString(sessionID) {
			return "", errors.New("invalid terminal session ID")
		}
		path = "/api/agent/terminal/session/" + sessionID
	}
	return (&url.URL{Scheme: "wss", Host: u.Host, Path: path}).String(), nil
}

func terminalWebSocketHeaders(cfg Config, ticket string) (http.Header, error) {
	if !terminalIDRE.MatchString(cfg.ServerID) || !validNodeToken(cfg.NodeToken) || ticket != "" && !validNodeToken(ticket) {
		return nil, errors.New("invalid terminal node authentication")
	}
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+cfg.NodeToken)
	headers.Set("X-CFSM-Server-Id", cfg.ServerID)
	if ticket != "" {
		headers.Set("X-CFSM-Terminal-Ticket", ticket)
	}
	return headers, nil
}
