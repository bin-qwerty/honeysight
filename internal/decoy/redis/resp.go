// Minimal RESP (REdis Serialization Protocol) codec — just enough to
// speak to real Redis clients: command parsing and the five reply types.
package redis

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Command is a parsed client request.
type Command struct {
	Name string
	Args []string
	Raw  string // "GET key" form — what detection rules see
}

func (c Command) String() string { return c.Raw }

// reader accumulates bytes and parses one RESP command at a time.
type reader struct {
	r   io.Reader
	buf []byte
}

func newReader(r io.Reader) *reader { return &reader{r: r} }

// readCommand blocks until one full command is parsed.
// It returns (cmd, nil), (nil, nil) on clean EOF or (nil, err) on a
// protocol violation.
func (rd *reader) readCommand() (*Command, error) {
	for {
		if cmd, ok, err := rd.tryParse(); ok || err != nil {
			return cmd, err
		}
		n, err := rd.fill()
		if n == 0 && err != nil {
			if err == io.EOF {
				return nil, nil // clean close
			}
			return nil, err
		}
	}
}

// fill appends fresh bytes to the buffer.
func (rd *reader) fill() (int, error) {
	tmp := make([]byte, 4096)
	n, err := rd.r.Read(tmp)
	rd.buf = append(rd.buf, tmp[:n]...)
	return n, err
}

// tryParse attempts to parse a command from the current buffer.
// ok=true means a command was consumed; otherwise the buffer is left
// untouched (more bytes needed).
func (rd *reader) tryParse() (*Command, bool, error) {
	b := rd.buf
	if len(b) == 0 {
		return nil, false, nil
	}

	// Inline command (telnet-style: "GET key\r\n").
	if b[0] != '*' && b[0] != '$' && b[0] != '+' && b[0] != '-' && b[0] != ':' {
		if i := bytesIndexCR(b); i >= 0 {
			line := strings.TrimRight(string(b[:i]), "\r\n")
			rd.buf = b[i+2:]
			if line == "" {
				return nil, false, nil
			}
			fields := strings.Fields(line)
			return &Command{Name: strings.ToUpper(fields[0]), Args: fields[1:], Raw: line}, true, nil
		}
		if len(b) > 512 {
			return nil, false, fmt.Errorf("inline line too long")
		}
		return nil, false, nil
	}

	cmd, rest, err := parseArray(b)
	if err != nil {
		return nil, false, err
	}
	if cmd == nil {
		return nil, false, nil // incomplete
	}
	rd.buf = rest
	return cmd, true, nil
}

// parseArray parses a `*N` array of bulk strings from b.
// Returns (nil, b, nil) when the buffer is incomplete.
func parseArray(b []byte) (*Command, []byte, error) {
	// "*N\r\n"
	if len(b) < 4 || b[0] != '*' {
		return nil, b, nil
	}
	crlf := bytesIndexCR(b[:4])
	if crlf < 0 {
		return nil, b, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b[1:crlf])))
	if err != nil || n < 1 || n > 1024 {
		return nil, nil, fmt.Errorf("bad array length")
	}
	off := crlf + 2
	if off > len(b) {
		return nil, b, nil
	}

	var args []string
	raw := strings.Builder{}
	for i := 0; i < n; i++ {
		if len(b) < off+2 || b[off] != '$' {
			return nil, b, nil
		}
		end := bytesIndexCR(b[off:])
		if end < 0 || off+end+2 > len(b) {
			return nil, b, nil
		}
		l, err := strconv.Atoi(strings.TrimSpace(string(b[off+1 : off+end])))
		if err != nil || l < 0 || l > 1024*1024 {
			return nil, nil, fmt.Errorf("bad bulk length")
		}
		start := off + end + 2
		if start+l+2 > len(b) {
			return nil, b, nil
		}
		arg := string(b[start : start+l])
		args = append(args, arg)
		if raw.Len() > 0 {
			raw.WriteByte(' ')
		}
		raw.WriteString(arg)
		off = start + l + 2
	}
	name := strings.ToUpper(args[0])
	return &Command{Name: name, Args: args[1:], Raw: raw.String()}, b[off:], nil
}

func bytesIndexCR(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}

// --- reply writing ---

// WriteSimpleString: +OK\r\n
func writeSimpleString(w io.Writer, s string) error {
	_, err := fmt.Fprintf(w, "+%s\r\n", s)
	return err
}

// WriteError: -ERR ...\r\n
func writeError(w io.Writer, s string) error {
	_, err := fmt.Fprintf(w, "-%s\r\n", s)
	return err
}

// WriteInteger: :N\r\n
func writeInteger(w io.Writer, n int64) error {
	_, err := fmt.Fprintf(w, ":%d\r\n", n)
	return err
}

// WriteBulkString: $len\r\n...\r\n ; nilBulk writes the null bulk string.
func WriteBulkString(w io.Writer, s string) error {
	if s == "" {
		return nilBulk(w)
	}
	_, err := fmt.Fprintf(w, "$%d\r\n%s\r\n", len(s), s)
	return err
}

func nilBulk(w io.Writer) error {
	_, err := io.WriteString(w, "$-1\r\n")
	return err
}

// WriteArray writes an array of bulk strings.
func WriteArray(w io.Writer, items []string) error {
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(items)); err != nil {
		return err
	}
	for _, it := range items {
		if err := WriteBulkString(w, it); err != nil {
			return err
		}
	}
	return nil
}
