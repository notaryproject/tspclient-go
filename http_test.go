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
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/tspclient-go/internal/hashutil"
	"github.com/notaryproject/tspclient-go/pki"
)

func TestHTTPTimestampGranted(t *testing.T) {
	// setup test server
	testResp, err := os.ReadFile("testdata/granted.tsq")
	if err != nil {
		t.Fatal("failed to read test response:", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = TimestampQuery
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimeStampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimeStampRequest.Body read error = %v", err)
		}

		// write reply
		w.Header().Set("Content-Type", TimestampReply)
		if _, err := w.Write(testResp); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer ts.Close()

	// do timestamp
	tsa, err := NewHTTPTimestamper(nil, ts.URL)
	if err != nil {
		t.Fatalf("NewHTTPTimestamper() error = %v", err)
	}
	message := []byte("notation")
	requestOpts := RequestOptions{
		Content:       message,
		HashAlgorithm: crypto.SHA256,
		HashAlgorithmParameters: asn1.RawValue{
			Tag:       5,
			FullBytes: []byte{5, 0},
		},
		NoNonce: true,
	}
	req, err := NewRequest(requestOpts)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	ctx := context.Background()
	resp, err := tsa.Timestamp(ctx, req)
	if err != nil {
		t.Fatalf("httpTimestamper.Timestamp() error = %v", err)
	}
	wantStatus := pki.StatusGranted
	if got := resp.Status.Status; got != wantStatus {
		t.Fatalf("Response.Status = %v, want %v", got, wantStatus)
	}

	// verify timestamp token
	token, err := resp.SignedToken()
	if err != nil {
		t.Fatalf("Response.SignedToken() error = %v", err)
	}
	roots := x509.NewCertPool()
	rootCABytes, err := os.ReadFile("testdata/GlobalSignRootCA.crt")
	if err != nil {
		t.Fatal("failed to read root CA certificate:", err)
	}
	if ok := roots.AppendCertsFromPEM(rootCABytes); !ok {
		t.Fatal("failed to load root CA certificate")
	}
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	certs, err := token.Verify(context.Background(), opts)
	if err != nil {
		t.Fatal("SignedToken.Verify() error =", err)
	}
	if got := len(certs); got != 4 {
		t.Fatalf("SignedToken.Verify() len([]*x509.Certificate) = %v, want %v", got, 4)
	}
	certThumbprint, err := hashutil.ComputeHash(crypto.SHA256, certs[0].Raw)
	if err != nil {
		t.Fatal("failed to compute certificate thumbprint:", err)
	}
	wantCertThumbprint := []byte{
		0x13, 0xd6, 0xe9, 0xc4, 0x20, 0xff, 0x6d, 0x4e, 0x27, 0x54, 0x72, 0x8c, 0x68, 0xe7, 0x78, 0x82,
		0x65, 0x64, 0x67, 0xdb, 0x9a, 0x19, 0x0f, 0x81, 0x65, 0x97, 0xf6, 0x7f, 0xb6, 0xcc, 0xc6, 0xf9,
	}
	if !bytes.Equal(certThumbprint, wantCertThumbprint) {
		t.Fatalf("SignedToken.Verify() = %v, want %v", certThumbprint, wantCertThumbprint)
	}
	info, err := token.Info()
	if err != nil {
		t.Fatal("SignedToken.Info() error =", err)
	}
	timestamp, accuracy, err := info.Timestamp(message)
	if err != nil {
		t.Errorf("TSTInfo.Timestamp() error = %v", err)
	}
	wantTimestamp := time.Date(2021, 9, 18, 11, 54, 34, 0, time.UTC)
	if timestamp != wantTimestamp {
		t.Errorf("TSTInfo.Timestamp() Timestamp = %v, want %v", timestamp, wantTimestamp)
	}
	wantAccuracy := time.Second
	if accuracy != wantAccuracy {
		t.Errorf("TSTInfo.Timestamp() Accuracy = %v, want %v", accuracy, wantAccuracy)
	}
}

func TestHTTPTimestampRejection(t *testing.T) {
	// setup test server
	testResp, err := os.ReadFile("testdata/rejection.tsq")
	if err != nil {
		t.Fatal("failed to read test response:", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = TimestampQuery
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimeStampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimeStampRequest.Body read error = %v", err)
		}

		// write reply
		w.Header().Set("Content-Type", TimestampReply)
		if _, err := w.Write(testResp); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer ts.Close()

	// do timestamp
	tsa, err := NewHTTPTimestamper(nil, ts.URL)
	if err != nil {
		t.Fatalf("NewHTTPTimestamper() error = %v", err)
	}
	requestOpts := RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
		HashAlgorithmParameters: asn1.RawValue{
			Tag:       5,
			FullBytes: []byte{5, 0},
		},
	}
	req, err := NewRequest(requestOpts)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	ctx := context.Background()
	expectedErrMsg := "invalid timestamping response: invalid response with status code 2: rejected. Failure info: unrecognized or unsupported Algorithm Identifier"
	_, err = tsa.Timestamp(ctx, req)
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestHTTPTimestampBadEndpoint(t *testing.T) {
	// setup test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// write reply
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if _, err := w.Write([]byte("{}")); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer ts.Close()

	// do timestamp
	tsa, err := NewHTTPTimestamper(nil, ts.URL)
	if err != nil {
		t.Fatalf("NewHTTPTimestamper() error = %v", err)
	}
	requestOpts := RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
		HashAlgorithmParameters: asn1.RawValue{
			Tag:       5,
			FullBytes: []byte{5, 0},
		},
	}
	req, err := NewRequest(requestOpts)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	ctx := context.Background()
	_, err = tsa.Timestamp(ctx, req)
	if err == nil {
		t.Fatalf("httpTimestamper.Timestamp() error = %v, wantErr %v", err, true)
	}
}

func TestHTTPTimestampEndpointNotFound(t *testing.T) {
	// setup test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	// do timestamp
	tsa, err := NewHTTPTimestamper(nil, ts.URL)
	if err != nil {
		t.Fatalf("NewHTTPTimestamper() error = %v", err)
	}
	requestOpts := RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
		HashAlgorithmParameters: asn1.RawValue{
			Tag:       5,
			FullBytes: []byte{5, 0},
		},
	}
	req, err := NewRequest(requestOpts)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	ctx := context.Background()
	_, err = tsa.Timestamp(ctx, req)
	if err == nil {
		t.Fatalf("httpTimestamper.Timestamp() error = %v, wantErr %v", err, true)
	}
}

func TestNewHTTPTimestamper(t *testing.T) {
	malformedURL := "http://[::1]/%"
	expectedErrMsg := `parse "http://[::1]/%": invalid URL escape "%"`
	if _, err := NewHTTPTimestamper(nil, malformedURL); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestHttpTimestamperTimestamp(t *testing.T) {
	// setup test server
	testResp, err := os.ReadFile("testdata/granted.tsq")
	if err != nil {
		t.Fatal("failed to read test response:", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = TimestampQuery
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimeStampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimeStampRequest.Body read error = %v", err)
		}

		// write reply
		w.Header().Set("Content-Type", TimestampReply)
		if _, err := w.Write(testResp); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer ts.Close()
	tsa, err := NewHTTPTimestamper(nil, ts.URL)
	if err != nil {
		t.Fatalf("NewHTTPTimestamper() error = %v", err)
	}
	expectedErrMsg := "malformed timestamping request: request cannot be nil"
	if _, err := tsa.Timestamp(context.Background(), nil); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
	requestOpts := RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
		HashAlgorithmParameters: asn1.RawValue{
			Tag:       5,
			FullBytes: []byte{5, 0},
		},
	}
	req, err := NewRequest(requestOpts)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	expectedErrMsg = "net/http: nil Context"
	if _, err := tsa.Timestamp(nil, req); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = TimestampQuery
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimeStampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimeStampRequest.Body read error = %v", err)
		}

		// write reply
		w.Header().Set("Content-Type", TimestampReply)
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write(testResp); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer ts.Close()
	tsa, err = NewHTTPTimestamper(nil, ts2.URL)
	if err != nil {
		t.Fatalf("NewHTTPTimestamper() error = %v", err)
	}
	expectedErrMsg = "https response bad status: 500 Internal Server Error"
	if _, err := tsa.Timestamp(context.Background(), req); err == nil || !strings.Contains(err.Error(), expectedErrMsg) {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	ts3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = TimestampQuery
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimeStampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimeStampRequest.Body read error = %v", err)
		}

		// write reply
		w.Header().Set("Content-Type", "invalid-response-header")
		if _, err := w.Write(testResp); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer ts.Close()
	tsa, err = NewHTTPTimestamper(nil, ts3.URL)
	if err != nil {
		t.Fatalf("NewHTTPTimestamper() error = %v", err)
	}
	expectedErrMsg = "unexpected response content type: invalid-response-header"
	if _, err := tsa.Timestamp(context.Background(), req); err == nil || !strings.Contains(err.Error(), expectedErrMsg) {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	malformedResp, err := os.ReadFile("testdata/malformed.tsq")
	if err != nil {
		t.Fatal("failed to read test response:", err)
	}
	ts4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = TimestampQuery
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimeStampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimeStampRequest.Body read error = %v", err)
		}

		// write reply
		w.Header().Set("Content-Type", TimestampReply)
		if _, err := w.Write(malformedResp); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer ts.Close()
	tsa, err = NewHTTPTimestamper(nil, ts4.URL)
	if err != nil {
		t.Fatalf("NewHTTPTimestamper() error = %v", err)
	}
	expectedErrMsg = "asn1: structure error"
	if _, err := tsa.Timestamp(context.Background(), req); err == nil || !strings.Contains(err.Error(), expectedErrMsg) {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	maxBodyLength = 0
	tsa, err = NewHTTPTimestamper(nil, ts.URL)
	if err != nil {
		t.Fatalf("NewHTTPTimestamper() error = %v", err)
	}
	expectedErrMsg = "unexpected large http response, max response body size allowed is 0 MiB"
	if _, err := tsa.Timestamp(context.Background(), req); err == nil || !strings.Contains(err.Error(), expectedErrMsg) {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}
