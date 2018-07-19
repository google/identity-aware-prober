/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

/*
The iaprober command serves as a server mode external prober for
Cloudprober (https://cloudprober.org).
*/

package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"

	epb "github.com/google/cloudprober/probes/external/proto"

	"github.com/golang/protobuf/proto"
	"github.com/google/cloudprober/probes/external/serverutils"
)

var (
	credentials      = flag.String("credentials", "", "Path to the service account JSON credentials")
	probeURL         = flag.String("url", "", "IAP-protected URL to probe")
	clientIDflag     = flag.String("clientid", "", "The Oauth2 ClientID for IAP")
	server           = flag.Bool("server", false, "Whether to run in server mode")
	oauthTimeoutFlag = flag.String("oauth_timeout", "10s", "The maximum time to wait for an OAuth token exchange")
	probeTimeoutFlag = flag.String("probe_timeout", "1m", "The maximum time to wait fetching a URL (in non-server mode)")
	codeRangesFlag   = flag.String("valid_code_ranges", "200,300", "The HTTP status codes that count as success. Format: 10-20;100-200. Used in non-server mode, or as the default in server-mode")
)

const (
	tokenURL = "https://www.googleapis.com/oauth2/v4/token"
)

type serviceCredentials struct {
	email string
	keyID string
	key   *rsa.PrivateKey
}

type serviceCredentialsTokenSource struct {
	credentials *serviceCredentials
	clientID    string
	timeout     time.Duration
}

func (s *serviceCredentials) TokenSource(clientID string, timeout time.Duration) *serviceCredentialsTokenSource {
	return &serviceCredentialsTokenSource{
		credentials: s,
		clientID:    clientID,
		timeout:     timeout,
	}
}

func (ts *serviceCredentialsTokenSource) Token() (*oauth2.Token, error) {
	iat := time.Now()
	exp := iat.Add(time.Hour)
	j, err := createSignedJWT(ts, iat, exp)
	if err != nil {
		return nil, fmt.Errorf("Error creating signed JWT: %v", err)
	}
	t, err := exchangeJWTForAccessToken(j, exp, ts.timeout)
	if err != nil {
		return nil, fmt.Errorf("Error exchanging JWT for access token: %v", err)
	}
	return t, nil
}

func readCredentialsFromJSON(filename string) (*serviceCredentials, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Error reading credentials file: %v", err)
	}

	// we need to specify a custom "target_audience" claim in our singed JWT token
	// that we exchange for an OpenID Connect token. Because the Go library's default
	// token source does not do that, we need to manually create our own token source.
	cfg, err := google.JWTConfigFromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("Error parsing JSON key: %v", err)
	}
	pk, err := extractKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Error extracting key: %v", err)
	}
	s := &serviceCredentials{
		email: cfg.Email,
		keyID: cfg.PrivateKeyID,
		key:   pk,
	}
	return s, nil
}

func createSignedJWT(ts *serviceCredentialsTokenSource, iat, exp time.Time) (string, error) {
	cs := &jws.ClaimSet{
		Iat: iat.Unix(),
		Exp: exp.Unix(),
		Iss: ts.credentials.email,
		Aud: tokenURL,
		Sub: ts.credentials.email,
		PrivateClaims: map[string]interface{}{
			"target_audience": ts.clientID,
		},
	}
	hdr := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     ts.credentials.keyID,
	}
	msg, err := jws.Encode(hdr, cs, ts.credentials.key)
	if err != nil {
		return "", fmt.Errorf("google: could not encode JWT: %v", err)
	}
	return msg, nil
}

func exchangeJWTForAccessToken(jwt string, exp time.Time, timeout time.Duration) (*oauth2.Token, error) {
	v := url.Values{}
	v.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	v.Set("assertion", jwt)

	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.PostForm("https://www.googleapis.com/oauth2/v4/token", v)
	if err != nil {
		return nil, fmt.Errorf("Error exchanging JWT for access token: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("Error reading access token: %v\n", err)
	}
	if c := resp.StatusCode; c != 200 {
		return nil, fmt.Errorf("Error exchanging JWT for access token: %v\n%v\n", resp.Status, string(body))
	}
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("Error reading token response: %v", err)
	}
	token := &oauth2.Token{
		AccessToken: tokenResponse.IDToken,
		Expiry:      exp,
	}
	return token, nil
}

func extractKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("private key should be a PEM or plain PKSC1 or PKCS8; parse error: %v", err)
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("The private key was not of the expected type (RSA)")
	}
	return parsed, nil
}

func get(ctx context.Context, ts oauth2.TokenSource, URL string) (*http.Response, error) {
	c := oauth2.NewClient(ctx, ts)
	resp, err := c.Get(URL)
	return resp, err
}

func probe(ctx context.Context, ts oauth2.TokenSource, URL string, codeRanges []codeRange) (string, error) {
	var payload []string

	startTime := time.Now()

	resp, err := get(ctx, ts, URL)
	if err != nil {
		return "", err
	}
	payload = append(payload, fmt.Sprintf("get_latency_ms %f", float64(time.Since(startTime).Nanoseconds())/1e6))

	// option good status filter:
	// "start-end; start-end

	if c := resp.StatusCode; !isCodeInRange(c, codeRanges) {
		return strings.Join(payload, "\n"), fmt.Errorf("non-200 status code: %v", c)
	}
	return strings.Join(payload, "\n"), nil
}

func optionsToMap(options []*epb.ProbeRequest_Option) map[string]string {
	optionMap := make(map[string]string)
	for _, o := range options {
		optionMap[*o.Name] = *o.Value
	}
	return optionMap
}

// a code range represents a range of status codes lower <= code <= upper
type codeRange struct {
	lower int
	upper int
}

func isCodeInRange(code int, codeRanges []codeRange) bool {
	for _, c := range codeRanges {
		if code >= c.lower && code <= c.upper {
			return true
		}
	}
	return false
}

// take a string that looks like:
// lower,upper;lower,upper
// or
// code ; code ; code
// to match single values
// and return a list of ranges
func parseCodeRange(input string) ([]codeRange, error) {
	var ranges []codeRange
	if input == "" {
		return ranges, nil
	}
	parts := strings.Split(strings.TrimSpace(input), ";")
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			continue
		}
		// part should look like "lower-upper"
		lu := strings.Split(part, "-")
		if len(lu) == 1 {
			code, err := strconv.ParseInt(strings.TrimSpace(lu[0]), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("Invalid code range(%s): %#v (cannot parse number: %v)", input, lu, err)
			}
			ranges = append(ranges, codeRange{int(code), int(code)})
		} else if len(lu) == 2 {
			lower, err := strconv.ParseInt(strings.TrimSpace(lu[0]), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("Invalid code range(%s): %#v (cannot parse number: %v)", input, lu, err)
			}
			upper, err := strconv.ParseInt(strings.TrimSpace(lu[1]), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("Invalid code range(%s): %#v (cannot parse number: %v)", input, lu, err)
			}
			ranges = append(ranges, codeRange{int(lower), int(upper)})
		} else {
			return nil, fmt.Errorf("Invalid code range(%#v): %#v does not have 2 elements", parts, lu)
		}
	}
	return ranges, nil
}

func main() {
	flag.Parse()

	if *credentials == "" {
		log.Fatal("Must specify a credentials file with --credentials")
	}

	oauthTimeout, err := time.ParseDuration(*oauthTimeoutFlag)
	if err != nil {
		log.Fatal(err)
	}

	c, err := readCredentialsFromJSON(*credentials)
	if err != nil {
		log.Fatalf("Error reading credentials: %v", err)
	}

	if *server {
		tokenSourceByClientID := make(map[string]oauth2.TokenSource)

		serverutils.Serve(func(request *epb.ProbeRequest, reply *epb.ProbeReply) {
			options := optionsToMap(request.Options)
			var URL, id string
			var ok bool
			var codeRangesOption string
			if URL, ok = options["url"]; !ok {
				reply.ErrorMessage = proto.String("No url specified in probe request")
				return
			}
			if id, ok = options["client_id"]; !ok {
				reply.ErrorMessage = proto.String("No client_id specified in probe request")
				return
			}
			if codeRangesOption, ok = options["valid_code_ranges"]; !ok {
				codeRangesOption = *codeRangesFlag
			}
			codeRanges, err := parseCodeRange(codeRangesOption)
			if err != nil {
				reply.ErrorMessage = proto.String(fmt.Sprintf("%v", err))
				return
			}
			ts, ok := tokenSourceByClientID[id]
			if !ok {
				ts = c.TokenSource(id, oauthTimeout)
				tokenSourceByClientID[id] = oauth2.ReuseTokenSource(nil, ts)
			}
			probeTimeout := time.Duration(*request.TimeLimit) * time.Millisecond
			ctx, _ := context.WithTimeout(context.Background(), probeTimeout)
			payload, err := probe(ctx, ts, URL, codeRanges)
			reply.Payload = proto.String(payload)
			if err != nil {
				reply.ErrorMessage = proto.String(err.Error())
			}
		})
	} else {
		ts := c.TokenSource(*clientIDflag, oauthTimeout)
		probeTimeout, err := time.ParseDuration(*probeTimeoutFlag)
		if err != nil {
			log.Fatal(err)
		}
		codeRanges, err := parseCodeRange(*codeRangesFlag)
		if err != nil {
			log.Fatal(err)
		}
		ctx, _ := context.WithTimeout(context.Background(), probeTimeout)
		payload, err := probe(ctx, ts, *probeURL, codeRanges)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(payload)
	}
}
