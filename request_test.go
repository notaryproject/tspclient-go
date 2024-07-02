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
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/notaryproject/tspclient-go/internal/hashutil"
	"github.com/notaryproject/tspclient-go/internal/oid"
)

func TestNewRequest(t *testing.T) {
	message := []byte("test")
	var malformedRequest *MalformedRequestError

	opts := RequestOptions{}
	expectedErrMsg := "malformed timestamping request: content to be time stamped cannot be empty"
	_, err := NewRequest(opts)
	if err == nil || !errors.As(err, &malformedRequest) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	opts = RequestOptions{
		Content:       message,
		HashAlgorithm: crypto.SHA1,
	}
	expectedErrMsg = fmt.Sprintf("malformed timestamping request: unsupported hashing algorithm: %s", crypto.SHA1)
	_, err = NewRequest(opts)
	if err == nil || !errors.As(err, &malformedRequest) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	opts = RequestOptions{
		Content:       message,
		HashAlgorithm: crypto.SHA256,
	}
	req, err := NewRequest(opts)
	if err != nil {
		t.Fatalf("expected nil error, but got %v", err)
	}
	if !reflect.DeepEqual(req.MessageImprint.HashAlgorithm.Parameters, asn1NullRawValue) {
		t.Fatalf("expected %v, but got %v", asn1NullRawValue, req.MessageImprint.HashAlgorithm.Parameters)
	}

	opts = RequestOptions{
		Content:                 message,
		HashAlgorithm:           crypto.SHA256,
		HashAlgorithmParameters: asn1.NullRawValue,
	}
	req, err = NewRequest(opts)
	if err != nil {
		t.Fatalf("expected nil error, but got %v", err)
	}
	if !reflect.DeepEqual(req.MessageImprint.HashAlgorithm.Parameters, asn1NullRawValue) {
		t.Fatalf("expected %v, but got %v", asn1NullRawValue, req.MessageImprint.HashAlgorithm.Parameters)
	}
}

func TestRequestMarshalBinary(t *testing.T) {
	var r *Request
	_, err := r.MarshalBinary()
	if err == nil || err.Error() != "nil request" {
		t.Fatalf("expected error 'nil request', but got %v", err)
	}

	opts := RequestOptions{
		Content:       []byte("test"),
		HashAlgorithm: crypto.SHA256,
	}
	req, err := NewRequest(opts)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	_, err = req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRequestUnmarshalBinary(t *testing.T) {
	var r *Request
	expectedErrMsg := "asn1: Unmarshal recipient value is nil *tspclient.Request"
	err := r.UnmarshalBinary([]byte("test"))
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestValidateRequest(t *testing.T) {
	var r *Request
	var malformedRequest *MalformedRequestError

	expectedErrMsg := "malformed timestamping request: request cannot be nil"
	err := r.Validate()
	if err == nil || !errors.As(err, &malformedRequest) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	r = &Request{
		Version: 2,
	}
	expectedErrMsg = "malformed timestamping request: request version must be 1, but got 2"
	err = r.Validate()
	if err == nil || !errors.As(err, &malformedRequest) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	r = &Request{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1},
			},
		},
	}
	expectedErrMsg = "malformed timestamping request: hash algorithm 1 is unavailable"
	err = r.Validate()
	if err == nil || !errors.As(err, &malformedRequest) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	digest, err := hashutil.ComputeHash(crypto.SHA384, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	r = &Request{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: oid.SHA256,
			},
			HashedMessage: digest,
		},
	}
	expectedErrMsg = "malformed timestamping request: hashed message is of incorrect size 48"
	err = r.Validate()
	if err == nil || !errors.As(err, &malformedRequest) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}
