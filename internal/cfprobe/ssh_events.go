package cfprobe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const sshQueueLimit = 1024

type sshLoginEvent struct {
	Sequence   int64  `json:"sequence"`
	OccurredAt int64  `json:"occurredAt"`
	User       string `json:"user"`
	Address    string `json:"address"`
	Method     string `json:"method"`
}
type sshEventAck struct {
	Stream   string `json:"stream"`
	Sequence int64  `json:"sequence"`
}
type sshEventReport struct {
	Version int             `json:"version"`
	Stream  string          `json:"stream"`
	Events  []sshLoginEvent `json:"events"`
	State   string          `json:"state"`
	Source  string          `json:"source"`
}
type sshCollectorState struct {
	Identity      string          `json:"identity"`
	Stream        string          `json:"stream"`
	Sequence      int64           `json:"sequence"`
	Source        string          `json:"source"`
	FileID        string          `json:"fileId"`
	Offset        int64           `json:"offset"`
	Discarding    bool            `json:"discarding"`
	Anchor        string          `json:"anchor"`
	JournalCursor string          `json:"journalCursor"`
	JournalSince  int64           `json:"journalSince"`
	Events        []sshLoginEvent `json:"events"`
	Enabled       bool            `json:"enabled"`
	Gap           bool            `json:"gap"`
}
type sshEventCollector struct {
	mu      sync.Mutex
	path    string
	state   sshCollectorState
	loaded  bool
	code    string
	offered int64
	ctx     context.Context
}

var sshAcceptedRE = regexp.MustCompile(`^Accepted (password|publickey|keyboard-interactive/pam|hostbased|gssapi-with-mic) for ([^\x00-\x20\x7f]{1,64}) from ([0-9a-fA-F:.]{1,64}(?:%[A-Za-z0-9_.:-]{1,32})?) port [0-9]+(?: ssh[12])?(?:[: ].*)?$`)
var sshProcessRE = regexp.MustCompile(` sshd(?:-(?:session|auth))?\[[0-9]+\]: `)

func parseSSHMessage(message string, at time.Time) (sshLoginEvent, bool) {
	m := sshAcceptedRE.FindStringSubmatch(message)
	if m == nil || at.IsZero() || net.ParseIP(strings.Split(m[3], "%")[0]) == nil {
		return sshLoginEvent{}, false
	}
	return sshLoginEvent{OccurredAt: at.UnixMilli(), Method: m[1], User: m[2], Address: m[3]}, true
}
func parseSSHAccepted(line string, now time.Time) (sshLoginEvent, bool) {
	p := sshProcessRE.FindStringIndex(line)
	if p == nil {
		return sshLoginEvent{}, false
	}
	fields := strings.Fields(line[:p[0]])
	if len(fields) < 2 {
		return sshLoginEvent{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, fields[0])
	if err != nil {
		if len(fields) < 4 {
			return sshLoginEvent{}, false
		}
		at, err = time.ParseInLocation("2006 Jan 2 15:04:05", strconv.Itoa(now.Year())+" "+strings.Join(fields[:3], " "), now.Location())
		if err != nil {
			return sshLoginEvent{}, false
		}
		if at.After(now.Add(24 * time.Hour)) {
			at = at.AddDate(-1, 0, 0)
		}
	}
	return parseSSHMessage(strings.TrimSuffix(line[p[1]:], "\r"), at)
}

func newSSHEventCollector(path string) *sshEventCollector {
	return &sshEventCollector{path: path, code: "disabled"}
}
func sshConfigIdentity(cfg Config) string {
	sum := sha256.Sum256([]byte(cfg.WorkerURL + "\x00" + cfg.ServerID + "\x00" + cfg.NodeToken))
	return hex.EncodeToString(sum[:])
}
func (c *sshEventCollector) prepare(cfg Config) (sshCollectorState, error) {
	if !c.loaded {
		f, err := openPrivateFile(c.path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return sshCollectorState{}, err
		}
		if err == nil {
			defer f.Close()
			d := json.NewDecoder(io.LimitReader(f, 512*1024))
			d.DisallowUnknownFields()
			if err := d.Decode(&c.state); err != nil {
				return sshCollectorState{}, err
			}
			if c.state.Sequence < 0 || c.state.Offset < 0 || len(c.state.Events) > sshQueueLimit || len(c.state.Stream) != 32 || len(c.state.JournalCursor) > 4096 {
				return sshCollectorState{}, errors.New("invalid SSH cursor state")
			}
			if c.state.Source != "" && !strings.Contains("|auth.log|secure|journal|", "|"+c.state.Source+"|") {
				return sshCollectorState{}, errors.New("invalid SSH source state")
			}
			var seq int64
			for _, e := range c.state.Events {
				if e.Sequence <= seq || e.Sequence > c.state.Sequence || e.User == "" || e.OccurredAt <= 0 {
					return sshCollectorState{}, errors.New("invalid SSH event queue")
				}
				seq = e.Sequence
			}
		}
		c.loaded = true
	}
	next := c.state
	next.Events = append([]sshLoginEvent(nil), c.state.Events...)
	identity := sshConfigIdentity(cfg)
	if next.Identity != identity {
		token := make([]byte, 16)
		if _, err := rand.Read(token); err != nil {
			return next, err
		}
		next = sshCollectorState{Identity: identity, Stream: hex.EncodeToString(token), Events: []sshLoginEvent{}}
		c.offered = 0
	}
	return next, nil
}
func (c *sshEventCollector) save(next sshCollectorState) error {
	if reflect.DeepEqual(next, c.state) {
		return nil
	}
	if err := ensurePrivateConfigDirectory(filepath.Dir(c.path)); err != nil {
		return err
	}
	if err := verifyPrivateParent(c.path); err != nil {
		return err
	}
	f, err := createPrivateTemp(filepath.Dir(c.path), ".ssh-events-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = protectPrivateFile(f); err == nil {
		err = json.NewEncoder(f).Encode(next)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = verifyPrivateParent(c.path)
	}
	if err == nil {
		err = os.Rename(f.Name(), c.path)
	}
	if err != nil {
		return err
	}
	c.state = next
	return nil
}
func (c *sshEventCollector) snapshot() sshEventReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshotLocked()
}
func (c *sshEventCollector) snapshotForConfig(cfg Config) sshEventReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.Identity != sshConfigIdentity(cfg) {
		state := "disabled"
		if cfg.SSHLoginEnabled {
			state = "unavailable"
			if c.code == "permission_denied" {
				state = c.code
			}
		}
		if c.code == "state_error" {
			state = "state_error"
		}
		return sshEventReport{Version: 1, Stream: "status", Events: []sshLoginEvent{}, State: state, Source: ""}
	}
	return c.snapshotLocked()
}
func (c *sshEventCollector) snapshotLocked() sshEventReport {
	events := append([]sshLoginEvent{}, c.state.Events...)
	if len(events) > 32 {
		events = events[:32]
	}
	if len(events) > 0 && events[len(events)-1].Sequence > c.offered {
		c.offered = events[len(events)-1].Sequence
	}
	stream := c.state.Stream
	if stream == "" {
		stream = "status"
	}
	return sshEventReport{Version: 1, Stream: stream, Events: events, State: c.code, Source: c.state.Source}
}
func (c *sshEventCollector) ack(ack sshEventAck) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ack.Stream != c.state.Stream || ack.Sequence <= 0 || ack.Sequence > c.offered {
		return
	}
	next := c.state
	next.Events = []sshLoginEvent{}
	for _, e := range c.state.Events {
		if e.Sequence > ack.Sequence {
			next.Events = append(next.Events, e)
		}
	}
	if len(next.Events) == len(c.state.Events) {
		return
	}
	if err := c.save(next); err != nil {
		c.code = "state_error"
	}
}

func (c *sshEventCollector) collectFile(cfg Config, path string, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	next, err := c.prepare(cfg)
	if err != nil {
		c.code = "state_error"
		return err
	}
	f, info, err := openSSHLog(path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			c.code = "permission_denied"
		} else {
			c.code = "unavailable"
		}
		return err
	}
	defer f.Close()
	key := sshFileID(f, info)
	source := filepath.Base(path)
	if source != "secure" {
		source = "auth.log"
	}
	if !cfg.SSHLoginEnabled {
		next.Enabled = false
		next.Source = source
		c.code = "disabled"
		return c.save(next)
	}
	if !next.Enabled || next.Source != source || next.FileID == "" {
		next.Enabled = true
		next.Source = source
		next.FileID = key
		next.Offset = info.Size()
		var last [1]byte
		if info.Size() > 0 {
			_, _ = f.ReadAt(last[:], info.Size()-1)
			next.Discarding = last[0] != '\n'
		}
		next.JournalCursor = ""
	} else if next.FileID != key {
		rotated, old, openErr := openSSHLog(path + ".1")
		if openErr == nil {
			if sshFileID(rotated, old) == next.FileID {
				if old.Size() < next.Offset {
					next.Gap = true
					next.Offset = 0
					next.Discarding = false
				}
				err = c.readSSHFile(rotated, &next, now)
			} else {
				next.Gap = true
			}
			rotated.Close()
			if err != nil {
				return err
			}
		} else {
			next.Gap = true
		}
		if len(next.Events) >= sshQueueLimit {
			c.code = "queue_full"
			return c.save(next)
		}
		next.FileID = key
		next.Offset = 0
		next.Discarding = false
	} else if info.Size() < next.Offset {
		next.Gap = true
		next.Offset = 0
		next.Discarding = false
	} else if next.Offset > 0 && next.Anchor != "" {
		anchor, err := sshCursorAnchor(f, next.Offset)
		if err != nil {
			return err
		}
		if anchor != next.Anchor {
			next.Gap = true
			next.Offset = 0
			next.Discarding = false
		}
	}
	if err = c.readSSHFile(f, &next, now); err != nil {
		return err
	}
	c.code = "watching"
	if next.Gap {
		c.code = "rotation_gap"
	}
	if len(next.Events) >= sshQueueLimit {
		c.code = "queue_full"
	}
	if err = c.save(next); err != nil {
		c.code = "state_error"
	}
	return err
}
func (c *sshEventCollector) readSSHFile(f *os.File, next *sshCollectorState, now time.Time) error {
	if _, err := f.Seek(next.Offset, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReaderSize(io.LimitReader(f, 128*1024), 16384)
	var consumed int64
	discard := next.Discarding
	for len(next.Events) < sshQueueLimit {
		line, err := r.ReadSlice('\n')
		consumed += int64(len(line))
		if err == bufio.ErrBufferFull {
			discard = true
			continue
		}
		if err == io.EOF {
			if discard {
				next.Offset += consumed
				next.Discarding = true
			}
			break
		}
		if err != nil {
			return err
		}
		if !discard {
			if e, ok := parseSSHAccepted(strings.TrimSuffix(string(line), "\n"), now); ok {
				next.Sequence++
				e.Sequence = next.Sequence
				next.Events = append(next.Events, e)
			}
		}
		next.Offset += consumed
		consumed = 0
		discard = false
		next.Discarding = false
	}
	anchor, err := sshCursorAnchor(f, next.Offset)
	if err != nil {
		return err
	}
	next.Anchor = anchor
	return nil
}

func sshCursorAnchor(f *os.File, offset int64) (string, error) {
	if offset == 0 {
		return "", nil
	}
	size := int64(64)
	if offset < size {
		size = offset
	}
	bytes := make([]byte, size)
	if _, err := f.ReadAt(bytes, offset-size); err != nil {
		return "", err
	}
	// Detect truncate-and-regrow without persisting raw authentication-log bytes.
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}

func (c *sshEventCollector) collectJournalRecords(cfg Config, records []byte, baseline bool, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	next, err := c.prepare(cfg)
	if err != nil {
		c.code = "state_error"
		return err
	}
	if !cfg.SSHLoginEnabled {
		next.Enabled = false
		c.code = "disabled"
		return c.save(next)
	}
	next.Source = "journal"
	next.Enabled = true
	next.FileID = ""
	next.Offset = 0
	if baseline {
		next.JournalSince = now.UnixMicro()
	}
	scanner := bufio.NewScanner(bytes.NewReader(records))
	scanner.Buffer(make([]byte, 4096), 65536)
	for scanner.Scan() {
		if len(next.Events) >= sshQueueLimit {
			break
		}
		var row struct {
			Cursor     string          `json:"__CURSOR"`
			Timestamp  string          `json:"__REALTIME_TIMESTAMP"`
			Identifier string          `json:"SYSLOG_IDENTIFIER"`
			Message    json.RawMessage `json:"MESSAGE"`
		}
		if json.Unmarshal(scanner.Bytes(), &row) != nil || row.Cursor == "" || len(row.Cursor) > 4096 {
			return errors.New("invalid journal record")
		}
		if row.Cursor == next.JournalCursor {
			continue
		}
		if !baseline && (row.Identifier == "sshd" || row.Identifier == "sshd-session" || row.Identifier == "sshd-auth") {
			var message string
			if json.Unmarshal(row.Message, &message) != nil {
				next.JournalCursor = row.Cursor
				continue
			}
			us, err := strconv.ParseInt(row.Timestamp, 10, 64)
			if err != nil {
				return errors.New("invalid journal time")
			}
			if e, ok := parseSSHMessage(message, time.UnixMicro(us)); ok {
				next.Sequence++
				e.Sequence = next.Sequence
				next.Events = append(next.Events, e)
			}
		}
		next.JournalCursor = row.Cursor
	}
	if err = scanner.Err(); err != nil {
		return err
	}
	c.code = "watching"
	if next.Gap {
		c.code = "rotation_gap"
	}
	if len(next.Events) >= sshQueueLimit {
		c.code = "queue_full"
	}
	if err = c.save(next); err != nil {
		c.code = "state_error"
	}
	return err
}

func (c *sshEventCollector) collect(cfg Config, now time.Time) {
	if runtime.GOOS != "linux" {
		c.mu.Lock()
		defer c.mu.Unlock()
		next, err := c.prepare(cfg)
		if err == nil {
			c.code = "unsupported"
			if !cfg.SSHLoginEnabled {
				c.code = "disabled"
			}
			err = c.save(next)
		}
		if err != nil {
			c.code = "state_error"
		}
		return
	}
	c.mu.Lock()
	next, err := c.prepare(cfg)
	if err != nil {
		c.code = "state_error"
		c.mu.Unlock()
		return
	}
	if !cfg.SSHLoginEnabled {
		next.Enabled = false
		c.code = "disabled"
		if c.save(next) != nil {
			c.code = "state_error"
		}
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	// Stay on one source. Switching would replay the same sshd authentication from both sinks.
	if next.Source == "journal" && next.Enabled {
		c.collectJournal(cfg, now)
		return
	}
	if next.Enabled && (next.Source == "auth.log" || next.Source == "secure") {
		_ = c.collectFile(cfg, "/var/log/"+next.Source, now)
		return
	}
	c.collectJournal(cfg, now)
	c.mu.Lock()
	journalReady := c.state.Enabled && c.state.Source == "journal"
	c.mu.Unlock()
	if journalReady {
		return
	}
	for _, path := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if _, err := os.Lstat(path); err == nil {
			if c.collectFile(cfg, path, now) == nil {
				return
			}
		}
	}
}
func (a *Agent) startSSHEvents(ctx context.Context) {
	a.sshEvents = newSSHEventCollector(filepath.Join(filepath.Dir(a.paths.ConfigFile), "ssh-events.json"))
	ctx, a.sshCancel = context.WithCancel(ctx)
	a.sshEvents.ctx = ctx
	a.sshDone = make(chan struct{})
	a.sshEvents.collect(a.configSnapshot(), time.Now())
	go func() {
		defer close(a.sshDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			a.sshEvents.collect(a.configSnapshot(), time.Now())
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
func (a *Agent) stopSSHEvents() {
	if a.sshCancel != nil {
		a.sshCancel()
		<-a.sshDone
	}
}

func (a *Agent) ackSSHEvents(ack sshEventAck) {
	if a.sshEvents == nil {
		return
	}
	a.sshEvents.mu.Lock()
	current := a.sshEvents.state.Identity == sshConfigIdentity(a.configSnapshot())
	a.sshEvents.mu.Unlock()
	if current {
		a.sshEvents.ack(ack)
	}
}

func openSSHLog(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, nil, errors.New("unsafe SSH authentication log")
	}
	f, err := openNodeTokenFile(path)
	if err != nil {
		return nil, nil, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() {
		f.Close()
		return nil, nil, errors.New("SSH log changed while opening")
	}
	if err := verifySSHLogOwner(after); err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, after, nil
}
