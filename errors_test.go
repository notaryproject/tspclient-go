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
	"errors"
	"testing"
)

var errTestInner = errors.New("test inner error")

func TestMalformedRequestError(t *testing.T) {
	newErr := MalformedRequestError{}
	expectedErrMsg := "malformed timestamping request"
	if newErr.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, newErr)
	}
}

func TestSignedTokenVerificationError(t *testing.T) {
	newErr := SignedTokenVerificationError{Msg: "test error msg"}
	expectedErrMsg := "failed to verify signed token: test error msg"
	if newErr.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, newErr)
	}

	newErr = SignedTokenVerificationError{Detail: errTestInner}
	expectedErrMsg = "failed to verify signed token: test inner error"
	if newErr.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, newErr)
	}

	innerErr := newErr.Unwrap()
	expectedErrMsg = "test inner error"
	if innerErr.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, newErr)
	}
}
