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
	"context"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/notaryproject/tspclient-go/internal/oid"
	"github.com/notaryproject/tspclient-go/pki"
)

func TestResponseMarshalBinary(t *testing.T) {
	var r *Response
	_, err := r.MarshalBinary()
	if err == nil || err.Error() != "nil response" {
		t.Fatalf("expected error nil response, but got %v", err)
	}

	testResponse := Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
	}
	_, err = (&testResponse).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
}

func TestResponseUnmarshalBinary(t *testing.T) {
	var r *Response
	expectedErrMsg := "asn1: Unmarshal recipient value is nil *tspclient.Response"
	err := r.UnmarshalBinary([]byte("test"))
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestValidateStatus(t *testing.T) {
	badResponse := Response{
		Status: pki.StatusInfo{
			Status: pki.StatusRejection,
		},
	}
	expectedErrMsg := "invalid timestamping response: invalid response with status code 2: rejected"
	err := (&badResponse).validateStatus()
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	badResponse = Response{
		Status: pki.StatusInfo{
			Status: pki.StatusRejection,
			FailInfo: asn1.BitString{
				Bytes:     []byte{0x80},
				BitLength: 1,
			},
		},
	}
	expectedErrMsg = "invalid timestamping response: invalid response with status code 2: rejected. Failure info: unrecognized or unsupported Algorithm Identifier"
	err = (&badResponse).validateStatus()
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	validResponse := Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
	}
	err = (&validResponse).validateStatus()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignedToken(t *testing.T) {
	badResponse := Response{
		Status: pki.StatusInfo{
			Status: pki.StatusRejection,
		},
	}
	expectedErrMsg := "invalid timestamping response: invalid response with status code 2: rejected"
	_, err := (&badResponse).SignedToken()
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	validResponse := Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
	}
	expectedErrMsg = "cms: syntax error: invalid signed data: failed to convert from BER to DER: asn1: syntax error: BER-encoded ASN.1 data structures is empty"
	_, err = (&validResponse).SignedToken()
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestValidateResponse(t *testing.T) {
	var invalidResponse *InvalidResponseError
	var req *Request
	var resp *Response

	expectedErrMsg := "invalid timestamping response: missing corresponding request"
	err := resp.Validate(req)
	if err == nil || !errors.As(err, &invalidResponse) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	req = &Request{
		Version: 1,
	}
	expectedErrMsg = "invalid timestamping response: response cannot be nil"
	err = resp.Validate(req)
	if err == nil || !errors.As(err, &invalidResponse) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	resp = &Response{
		Status: pki.StatusInfo{
			Status: pki.StatusRejection,
		},
	}
	expectedErrMsg = "invalid timestamping response: invalid response with status code 2: rejected"
	err = resp.Validate(req)
	if err == nil || !errors.As(err, &invalidResponse) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	resp = &Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
	}
	expectedErrMsg = "invalid timestamping response: cms: syntax error: invalid signed data: failed to convert from BER to DER: asn1: syntax error: BER-encoded ASN.1 data structures is empty"
	err = resp.Validate(req)
	if err == nil || !errors.As(err, &invalidResponse) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	token, err := os.ReadFile("testdata/TimeStampTokenWithInvalidTSTInfo.p7s")
	if err != nil {
		t.Fatal("failed to read timestamp token from file:", err)
	}
	resp = &Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
		TimeStampToken: asn1.RawValue{
			FullBytes: token,
		},
	}
	expectedErrMsg = "invalid timestamping response: cannot unmarshal TSTInfo from timestamp token: asn1: structure error: tags don't match (23 vs {class:0 tag:16 length:3 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:24 set:false omitEmpty:false} Time @89"
	err = resp.Validate(req)
	if err == nil || !errors.As(err, &invalidResponse) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	req = &Request{}
	token, err = os.ReadFile("testdata/TimeStampTokenWithTSTInfoVersion2.p7s")
	if err != nil {
		t.Fatal("failed to read timestamp token from file:", err)
	}
	resp = &Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
		TimeStampToken: asn1.RawValue{
			FullBytes: token,
		},
	}
	expectedErrMsg = "invalid timestamping response: timestamp token info version must be 1, but got 2"
	err = resp.Validate(req)
	if err == nil || !errors.As(err, &invalidResponse) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	req = &Request{
		ReqPolicy: asn1.ObjectIdentifier{1},
	}
	token, err = os.ReadFile("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal("failed to read timestamp token from file:", err)
	}
	resp = &Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
		TimeStampToken: asn1.RawValue{
			FullBytes: token,
		},
	}
	expectedErrMsg = "invalid timestamping response: policy in response 1.3.6.1.4.1.4146.2.3 does not match policy in request 1"
	err = resp.Validate(req)
	if err == nil || !errors.As(err, &invalidResponse) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	req = &Request{}
	token, err = os.ReadFile("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal("failed to read timestamp token from file:", err)
	}
	resp = &Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
		TimeStampToken: asn1.RawValue{
			FullBytes: token,
		},
	}
	expectedErrMsg = "invalid timestamping response: message imprint in response {HashAlgorithm:{Algorithm:2.16.840.1.101.3.4.2.1 Parameters:{Class:0 Tag:5 IsCompound:false Bytes:[] FullBytes:[5 0]}} HashedMessage:[131 38 244 112 157 64 29 250 191 167 131 2 251 28 222 160 241 128 72 164 64 64 194 18 189 142 40 218 107 198 81 199]} does not match with request {HashAlgorithm:{Algorithm: Parameters:{Class:0 Tag:0 IsCompound:false Bytes:[] FullBytes:[]}} HashedMessage:[]}"
	err = resp.Validate(req)
	if err == nil || !errors.As(err, &invalidResponse) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	digest, err := hex.DecodeString("8326f4709d401dfabfa78302fb1cdea0f18048a44040c212bd8e28da6bc651c7")
	if err != nil {
		t.Fatal(err)
	}
	messageImprint := MessageImprint{
		HashAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid.SHA256,
			Parameters: asn1.RawValue{
				Class:     0,
				Tag:       5,
				FullBytes: []byte{5, 0},
			},
		},
		HashedMessage: digest,
	}
	req = &Request{
		MessageImprint: messageImprint,
		Nonce:          big.NewInt(63456),
	}
	token, err = os.ReadFile("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal("failed to read timestamp token from file:", err)
	}
	resp = &Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
		TimeStampToken: asn1.RawValue{
			FullBytes: token,
		},
	}
	expectedErrMsg = "invalid timestamping response: nonce in response <nil> does not match nonce in request 63456"
	err = resp.Validate(req)
	if err == nil || !errors.As(err, &invalidResponse) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	req = &Request{
		MessageImprint: messageImprint,
		CertReq:        true,
	}
	token, err = os.ReadFile("testdata/TimeStampTokenWithoutCertificate.p7s")
	if err != nil {
		t.Fatal("failed to read timestamp token from file:", err)
	}
	resp = &Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
		TimeStampToken: asn1.RawValue{
			FullBytes: token,
		},
	}
	expectedErrMsg = "invalid timestamping response: certReq is True in request, but did not find any TSA signing certificate in the response"
	err = resp.Validate(req)
	if err == nil || !errors.As(err, &invalidResponse) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	req = &Request{
		MessageImprint: messageImprint,
		CertReq:        false,
	}
	token, err = os.ReadFile("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal("failed to read timestamp token from file:", err)
	}
	resp = &Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
		TimeStampToken: asn1.RawValue{
			FullBytes: token,
		},
	}
	expectedErrMsg = "invalid timestamping response: certReq is False in request, but certificates field is included in the response"
	err = resp.Validate(req)
	if err == nil || !errors.As(err, &invalidResponse) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	req = &Request{
		Version:        1,
		MessageImprint: messageImprint,
		ReqPolicy:      asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4146, 2, 3},
		CertReq:        true,
	}
	token, err = os.ReadFile("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal("failed to read timestamp token from file:", err)
	}
	resp = &Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
		TimeStampToken: asn1.RawValue{
			FullBytes: token,
		},
	}
	err = resp.Validate(req)
	if err != nil {
		t.Fatalf("expected nil error, but got %v", err)
	}

	req = &Request{
		Version:        1,
		MessageImprint: messageImprint,
		ReqPolicy:      asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4146, 2, 3},
		CertReq:        false,
	}
	token, err = os.ReadFile("testdata/TimeStampTokenWithoutCertificate.p7s")
	if err != nil {
		t.Fatal("failed to read timestamp token from file:", err)
	}
	resp = &Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
		TimeStampToken: asn1.RawValue{
			FullBytes: token,
		},
	}
	err = resp.Validate(req)
	if err != nil {
		t.Fatalf("expected nil error, but got %v", err)
	}
}

func TestTSAWithGenTimeNotUTC(t *testing.T) {
	// prepare TSA
	loc := time.FixedZone("UTC+8", 8*60*60)
	now := time.Date(2021, 9, 18, 11, 54, 34, 0, loc)
	tsa, err := newTestTSA(false, true)
	if err != nil {
		t.Fatalf("NewTSA() error = %v", err)
	}
	tsa.nowFunc = func() time.Time {
		return now
	}
	tsa.malformedTimeZone = true

	// do timestamp
	requestOpts := RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
		CertReq:       true,
	}
	req, err := NewRequest(requestOpts)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	ctx := context.Background()
	resp, err := tsa.Timestamp(ctx, req)
	if err != nil {
		t.Fatalf("TSA.Timestamp() error = %v", err)
	}
	wantStatus := pki.StatusGranted
	if got := resp.Status.Status; got != wantStatus {
		t.Fatalf("Response.Status = %v, want %v", got, wantStatus)
	}

	expectedErrMsg := "invalid timestamping response: TSTInfo genTime must be in UTC, but got Local"
	var invalidResponse *InvalidResponseError
	err = resp.Validate(req)
	if err == nil || !errors.As(err, &invalidResponse) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}
