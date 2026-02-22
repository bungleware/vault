package logger

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// ANSI codes
const (
	reset  = "\033[0m"
	dim    = "\033[2m"
	red    = "\033[31m"
	yellow = "\033[33m"
	green  = "\033[32m"
	cyan   = "\033[36m"
	white  = "\033[97m"
)

type PrettyHandler struct {
	opts  slog.HandlerOptions
	mu    sync.Mutex
	out   io.Writer
	color bool
	attrs []slog.Attr
	group string
}

func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

func NewPrettyHandler(out io.Writer, opts *slog.HandlerOptions) *PrettyHandler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	color := false
	if f, ok := out.(*os.File); ok {
		color = isTerminal(f)
	}
	return &PrettyHandler{opts: *opts, out: out, color: color}
}

func (h *PrettyHandler) Enabled(_ context.Context, level slog.Level) bool {
	min := h.opts.Level
	if min == nil {
		min = slog.LevelInfo
	}
	return level >= min.Level()
}

func (h *PrettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(clone.attrs[:len(clone.attrs):len(clone.attrs)], attrs...)
	return &clone
}

func (h *PrettyHandler) WithGroup(name string) slog.Handler {
	clone := *h
	if h.group != "" {
		clone.group = h.group + "." + name
	} else {
		clone.group = name
	}
	return &clone
}

func (h *PrettyHandler) Handle(_ context.Context, r slog.Record) error {
	var buf bytes.Buffer

	// Time: HH:MM:SS
	t := r.Time.Format(time.TimeOnly)
	if h.color {
		buf.WriteString(dim + t + reset)
	} else {
		buf.WriteString(t)
	}
	buf.WriteByte(' ')

	// Level
	var levelStr string
	if h.color {
		switch {
		case r.Level >= slog.LevelError:
			levelStr = red + "ERR" + reset
		case r.Level >= slog.LevelWarn:
			levelStr = yellow + "WRN" + reset
		case r.Level >= slog.LevelInfo:
			levelStr = green + "INF" + reset
		default:
			levelStr = cyan + "DBG" + reset
		}
	} else {
		switch {
		case r.Level >= slog.LevelError:
			levelStr = "ERR"
		case r.Level >= slog.LevelWarn:
			levelStr = "WRN"
		case r.Level >= slog.LevelInfo:
			levelStr = "INF"
		default:
			levelStr = "DBG"
		}
	}
	buf.WriteString(levelStr)
	buf.WriteByte(' ')

	// Message
	if h.color {
		buf.WriteString(white + r.Message + reset)
	} else {
		buf.WriteString(r.Message)
	}

	// Attributes: pre-set + record
	var attrBuf bytes.Buffer
	writeAttr := func(a slog.Attr) {
		a.Value = a.Value.Resolve()
		if a.Equal(slog.Attr{}) {
			return
		}
		attrBuf.WriteByte(' ')
		key := a.Key
		if h.group != "" {
			key = h.group + "." + key
		}
		if h.color {
			attrBuf.WriteString(dim + key + "=" + reset)
		} else {
			attrBuf.WriteString(key + "=")
		}
		attrBuf.WriteString(formatValue(a.Value))
	}
	for _, a := range h.attrs {
		writeAttr(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(a)
		return true
	})
	buf.Write(attrBuf.Bytes())
	buf.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.out.Write(buf.Bytes())
	return err
}

func formatValue(v slog.Value) string {
	switch v.Kind() {
	case slog.KindString:
		s := v.String()
		if strings.ContainsAny(s, " \t\n\"") {
			return strconv.Quote(s)
		}
		return s
	case slog.KindTime:
		return v.Time().Format(time.RFC3339)
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindGroup:
		var b strings.Builder
		b.WriteByte('{')
		for i, a := range v.Group() {
			if i > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(a.Key)
			b.WriteByte('=')
			b.WriteString(formatValue(a.Value))
		}
		b.WriteByte('}')
		return b.String()
	default:
		return fmt.Sprintf("%v", v.Any())
	}
}
