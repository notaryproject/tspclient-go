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
)

// maxBodyLength specifies the max content can be received from the remote
// server.
// The legnth of a regular TSA response with certificates is usually less than
// 10 KiB.
var maxBodyLength = 1 * 1024 * 1024 // 1 MiB

// TimestampQuery is the content-type of timestamp query.
// RFC 3161 3.4
const TimestampQuery = "application/timestamp-query"

// TimestampReply is the content-type of timestamp reply
// RFC 3161 3.4
const TimestampReply = "application/timestamp-reply"

// httpTimestamper is a HTTP-based timestamper.
type httpTimestamper struct {
	rt       http.RoundTripper
	endpoint string
}

// NewHTTPTimestamper creates a HTTP-based timestamper with the endpoint
// provided by the TSA.
// http.DefaultTransport is used if nil RoundTripper is passed.
func NewHTTPTimestamper(rt http.RoundTripper, endpoint string) (Timestamper, error) {
	if rt == nil {
		rt = http.DefaultTransport
	}
	if _, err := url.Parse(endpoint); err != nil {
		return nil, err
	}
	return &httpTimestamper{
		rt:       rt,
		endpoint: endpoint,
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
	hReq.Header.Set("Content-Type", TimestampQuery)

	// send the request to the remote TSA server
	hResp, err := ts.rt.RoundTrip(hReq)
	if err != nil {
		return nil, err
	}
	defer hResp.Body.Close()

	// verify HTTP response
	if hResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %q: https response bad status: %s with response body: %v", http.MethodPost, ts.endpoint, hResp.Status, hResp.Body)
	}
	if contentType := hResp.Header.Get("Content-Type"); contentType != TimestampReply {
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
