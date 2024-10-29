// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tspclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// maxBodyLength specifies the max content can be received from the remote
// server.
// The legnth of a regular TSA response with certificates is usually less than
// 10 KiB.
var maxBodyLength = 1 * 1024 * 1024 // 1 MiB

// const for MediaTypes defined in RFC 3161 3.4
const (
	// MediaTypeTimestampQuery is the content-type of timestamp query.
	// RFC 3161 3.4
	MediaTypeTimestampQuery = "application/timestamp-query"

	// MediaTypeTimestampReply is the content-type of timestamp reply
	// RFC 3161 3.4
	MediaTypeTimestampReply = "application/timestamp-reply"
)

// httpTimestamper is a HTTP-based timestamper.
type httpTimestamper struct {
	httpClient *http.Client
	endpoint   string
}

// NewHTTPTimestamper creates a HTTP-based timestamper with the endpoint
// provided by the TSA.
// http.DefaultTransport is used if nil RoundTripper is passed.
func NewHTTPTimestamper(httpClient *http.Client, endpoint string) (Timestamper, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	tsaURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if tsaURL.Scheme == "" {
		return nil, fmt.Errorf("endpoint %q: scheme cannot be empty", endpoint)
	}
	if tsaURL.Scheme != "http" && tsaURL.Scheme != "https" {
		return nil, fmt.Errorf("endpoint %q: scheme must be http or https, but got %q", endpoint, tsaURL.Scheme)
	}
	if tsaURL.Host == "" {
		return nil, fmt.Errorf("endpoint %q: host cannot be empty", endpoint)
	}
	return &httpTimestamper{
		httpClient: httpClient,
		endpoint:   endpoint,
	}, nil
}

// Timestamp sends the request to the remote TSA server for timestamping.
//
// Reference: RFC 3161 3.4 Time-Stamp Protocol via HTTP
func (ts *httpTimestamper) Timestamp(ctx context.Context, req *Request) (*Response, error) {
	// sanity check
	if err := req.Validate(); err != nil {
		return nil, err
	}

	// prepare for http request
	reqBytes, err := req.MarshalBinary()
	if err != nil {
		return nil, err
	}
	hReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.endpoint, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}
	hReq.Header.Set("Content-Type", MediaTypeTimestampQuery)

	// send the request to the remote TSA server
	hResp, err := ts.httpClient.Do(hReq)
	if err != nil {
		return nil, err
	}
	defer hResp.Body.Close()

	// verify HTTP response
	if hResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %q: https response bad status: %s", http.MethodPost, ts.endpoint, hResp.Status)
	}
	if contentType := hResp.Header.Get("Content-Type"); contentType != MediaTypeTimestampReply {
		return nil, fmt.Errorf("%s %q: unexpected response content type: %s", http.MethodPost, ts.endpoint, contentType)
	}

	// read TSA response
	lr := &io.LimitedReader{
		R: hResp.Body,
		N: int64(maxBodyLength),
	}
	respBytes, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if lr.N == 0 {
		return nil, fmt.Errorf("%s %q: unexpected large http response, max response body size allowed is %d MiB", hResp.Request.Method, hResp.Request.URL, maxBodyLength/1024/1024)
	}
	var resp Response
	if err := resp.UnmarshalBinary(respBytes); err != nil {
		return nil, err
	}
	// validate response against RFC 3161
	if err := resp.Validate(req); err != nil {
		return nil, err
	}
	return &resp, nil
}
