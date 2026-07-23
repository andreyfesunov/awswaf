package awswaf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"mime/multipart"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

type Waf struct {
	Session     tlsclient.HttpClient
	gokuProps   GokuProps
	Host        string
	Domain      string
	UserAgent   string
	challengeJS challengeJSConfig
}

type challengeJSConfig struct {
	challengeTypes map[string]string
	solutionField  string
	metadataField  string
	bandwidthSizes map[int]int
}

func parseChallengeJS(js string) challengeJSConfig {
	cfg := challengeJSConfig{
		challengeTypes: map[string]string{},
		solutionField:  "solution_data",
		metadataField:  "solution_metadata",
		bandwidthSizes: map[int]int{},
	}

	if strings.TrimSpace(js) == "" {
		return cfg
	}

	reType := regexp.MustCompile(`'(h[0-9a-f]{8,})'[^=]{0,80}=\s*'((?:mp_)?verify)'`)
	for _, m := range reType.FindAllStringSubmatch(js, -1) {
		cfg.challengeTypes[m[1]] = m[2]
	}

	reField := regexp.MustCompile(`'verify'\s*,\s*'\w+'\s*:\s*'(solution_\w+)'\s*,\s*'\w+'\s*:\s*'(solution_\w+)'`)
	if m := reField.FindStringSubmatch(js); len(m) == 3 {
		cfg.solutionField = m[1]
		cfg.metadataField = m[2]
	}

	reHex := regexp.MustCompile(`case\s+0x1:return\s+(0x[0-9a-f]+);.*?case\s+0x2:return[^;]*\((0x[0-9a-f]+),(0x[0-9a-f]+)\);.*?case\s+0x3:return[^;]*\((0x[0-9a-f]+),(0x[0-9a-f]+)\);.*?case\s+0x4:return[^;]*\((0x[0-9a-f]+),(0x[0-9a-f]+)\);.*?case\s+0x5:return[^;]*\((0x[0-9a-f]+),(0x[0-9a-f]+)\)`)
	if m := reHex.FindStringSubmatch(strings.ToLower(js)); len(m) == 10 {
		parseHex := func(s string) int {
			v, err := strconv.ParseInt(s, 0, 64)
			if err != nil {
				return 0
			}
			return int(v)
		}
		cfg.bandwidthSizes[1] = parseHex(m[1])
		cfg.bandwidthSizes[2] = parseHex(m[2]) * parseHex(m[3])
		cfg.bandwidthSizes[3] = parseHex(m[4]) * parseHex(m[5])
		cfg.bandwidthSizes[4] = parseHex(m[6]) * parseHex(m[7])
		cfg.bandwidthSizes[5] = parseHex(m[8]) * parseHex(m[9])
	}

	return cfg
}

func NewWaf(host, domain, userAgent string, gokuProps GokuProps, challengeJS, proxy string, timeoutSec int) (*Waf, error) {
	if timeoutSec <= 0 {
		timeoutSec = 120
	}
	options := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(timeoutSec),
		tlsclient.WithClientProfile(profiles.Chrome_133),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
	}
	if proxy != "" {
		options = append(options, tlsclient.WithProxyUrl(proxy))
	}
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
	if err != nil {
		return nil, err
	}

	return &Waf{
		Session:     client,
		gokuProps:   gokuProps,
		Host:        host,
		Domain:      domain,
		UserAgent:   userAgent,
		challengeJS: parseChallengeJS(challengeJS),
	}, nil
}

func Extract(html string) (GokuProps, string, error) {
	const marker = "window.gokuProps = "
	start := strings.Index(html, marker)
	if start == -1 {
		return GokuProps{}, "", fmt.Errorf("gokuProps not found")
	}

	start += len(marker)
	end := strings.Index(html[start:], ";")
	if end == -1 {
		return GokuProps{}, "", fmt.Errorf("end of gokuProps not found")
	}

	var gokuProps GokuProps
	if err := json.Unmarshal([]byte(html[start:start+end]), &gokuProps); err != nil {
		return GokuProps{}, "", err
	}

	idx := strings.Index(html, `src="https://`)
	if idx == -1 {
		return gokuProps, "", nil
	}
	idx += len(`src="https://`)
	tail := html[idx:]
	jsEnd := strings.Index(tail, "/challenge.js")
	if jsEnd == -1 {
		return gokuProps, "", nil
	}
	host := tail[:jsEnd]

	return gokuProps, host, nil
}

func (a *Waf) GetInputs() (Inputs, error) {
	u := fmt.Sprintf("https://%s/inputs?client=browser", a.Host)

	req, err := fhttp.NewRequest(fhttp.MethodGet, u, nil)
	if err != nil {
		return Inputs{}, err
	}
	req.Header = fhttp.Header{
		"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {"en-US,en;q=0.9"},
		"pragma":             {"no-cache"},
		"priority":           {"u=0, i"},
		"sec-ch-ua-mobile":   {"?0"},
		"sec-ch-ua-platform": {`"Windows"`},
		"sec-fetch-dest":     {"empty"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-site":     {"cross-site"},
		"user-agent":         {a.UserAgent},
		fhttp.HeaderOrderKey: {
			"accept",
			"accept-language",
			"accept-encoding",
			"pragma",
			"priority",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"sec-fetch-dest",
			"sec-fetch-mode",
			"sec-fetch-site",
			"user-agent",
		},
	}

	resp, err := a.Session.Do(req)
	if err != nil {
		return Inputs{}, err
	}
	defer resp.Body.Close()

	var out Inputs
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Inputs{}, err
	}
	return out, nil
}

func (a *Waf) BuildPayload(inputs Inputs) (*Verify, error) {
	checksum, fpPayload, err := GetFP(a.UserAgent)
	if err != nil {
		return nil, err
	}

	sol, err := SolveChallenge(
		inputs.ChallengeType, inputs.Challenge.Input,
		checksum, inputs.Difficulty, a.challengeJS.bandwidthSizes,
	)
	if err != nil {
		return nil, err
	}

	signals := []VerifySignals{{
		Name: "Zoey",
		Value: ValueVerifySignals{
			Present: fpPayload,
		},
	}}

	var metrics []VerifyMetrics
	for _, m := range []VerifyMetrics{
		{"2", rand.Float64(), "2"},
		{"100", 0, "2"}, {"101", 0, "2"},
		{"102", 0, "2"}, {"103", 8, "2"},
		{"104", 0, "2"}, {"105", 0, "2"},
		{"106", 0, "2"}, {"107", 0, "2"},
		{"108", 1, "2"}, {"undefined", 0, "2"},
		{"110", 0, "2"}, {"111", 2, "2"},
		{"112", 0, "2"}, {"undefined", 0, "2"},
		{"3", 4, "2"}, {"7", 0, "4"},
		{"1", rand.Float64()*(20-10) + 10, "2"},
		{"4", 36.5, "2"},
		{"5", rand.Float64(), "2"},
		{"6", rand.Float64()*(60-50) + 50, "2"},
		{"0", rand.Float64()*(140-130) + 130, "2"},
		{"8", 1, "4"},
	} {
		metrics = append(metrics, VerifyMetrics{
			Name:  m.Name,
			Value: m.Value,
			Unit:  m.Unit,
		})
	}

	return &Verify{
		Challenge:     inputs.Challenge,
		Solution:      sol,
		Signals:       signals,
		Checksum:      checksum,
		ExistingToken: nil,
		Client:        "Browser",
		Domain:        a.Domain,
		Metrics:       metrics,
		GokuProps:     a.gokuProps,
	}, nil
}

func (a *Waf) resolveEndpoint(challengeType string) string {
	if ep, ok := a.challengeJS.challengeTypes[challengeType]; ok {
		return ep
	}
	for prefix, ep := range a.challengeJS.challengeTypes {
		if strings.HasPrefix(challengeType, prefix) {
			return ep
		}
	}
	if challengeType == "ha9faaffd31b4d5ede2a2e19d2d7fd525f66fee61911511960dcbb52d3c48ce25" {
		return "mp_verify"
	}
	return "verify"
}

func (a *Waf) verifyJSON(payload *Verify, endpoint string) (string, error) {
	u := fmt.Sprintf("https://%s/%s", a.Host, endpoint)
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := fhttp.NewRequest(fhttp.MethodPost, u, strings.NewReader(string(data)))
	if err != nil {
		return "", err
	}
	req.Header = fhttp.Header{
		"accept":             {"*/*"},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"connection":         {"keep-alive"},
		"accept-language":    {"en-US,en;q=0.9"},
		"content-type":       {"text/plain;charset=UTF-8"},
		"priority":           {"u=1, i"},
		"sec-ch-ua-mobile":   {"?0"},
		"sec-ch-ua-platform": {`"Windows"`},
		"sec-fetch-dest":     {"empty"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-site":     {"cross-site"},
		"user-agent":         {a.UserAgent},
		fhttp.HeaderOrderKey: {
			"accept",
			"accept-encoding",
			"accept-language",
			"connection",
			"content-length",
			"content-type",
			"priority",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"sec-fetch-dest",
			"sec-fetch-mode",
			"sec-fetch-site",
			"user-agent",
		},
	}

	resp, err := a.Session.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	var out VerifyRes
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}

	return out.Token, nil
}

func (a *Waf) verifyMultipart(payload *Verify, endpoint string) (string, error) {
	u := fmt.Sprintf("https://%s/%s", a.Host, endpoint)

	copyPayload := *payload
	solution := copyPayload.Solution
	copyPayload.Solution = ""

	meta, err := json.Marshal(copyPayload)
	if err != nil {
		return "", err
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField(a.challengeJS.solutionField, solution)
	_ = w.WriteField(a.challengeJS.metadataField, string(meta))
	if err := w.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, u, &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("user-agent", a.UserAgent)
	req.Header.Set("content-type", w.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var out VerifyRes
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Token, nil
}

func (a *Waf) Run() (string, error) {
	inputs, err := a.GetInputs()
	if err != nil {
		return "", err
	}

	payload, err := a.BuildPayload(inputs)
	if err != nil {
		return "", err
	}
	endpoint := a.resolveEndpoint(inputs.ChallengeType)
	if endpoint == "mp_verify" {
		return a.verifyMultipart(payload, endpoint)
	}
	return a.verifyJSON(payload, endpoint)
}
