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

// Package pki contains Status of a timestamping response defined in RFC 3161.
package pki

import (
	"errors"
	"testing"
)

func TestFailureInfoError(t *testing.T) {
	testData := []string{
		"unrecognized or unsupported Algorithm Identifier",
		"transaction not permitted or supported",
		"the data submitted has the wrong format",
		"the TSA's time source is not available",
		"the requested TSA policy is not supported by the TSA",
		"the requested extension is not supported by the TSA",
		"the additional information requested could not be understood or is not available",
		"the request cannot be handled due to system failure",
	}
	for idx, f := range failureInfos {
		if f.Error().Error() != testData[idx] {
			t.Fatalf("expected %s, but got %s", f.Error().Error(), testData[idx])
		}
	}

	unknown := FailureInfo(1)
	if unknown.Error().Error() != "unknown PKIFailureInfo 1" {
		t.Fatalf("expected %s, but got %s", "unknown PKIFailureInfo", unknown.Error().Error())
	}

	failureInfoErr := FailureInfoError{
		Detail: errors.Join(FailureInfoBadRequest.Error(), FailureInfoBadDataFormat.Error()),
	}
	expectedErrMsg := "transaction not permitted or supported; the data submitted has the wrong format"
	if failureInfoErr.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, failureInfoErr.Error())
	}
	innerErr := failureInfoErr.Unwrap()
	expectedErrMsg = "transaction not permitted or supported\nthe data submitted has the wrong format"
	if innerErr.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, innerErr)
	}

	failureInfoErr = FailureInfoError{}
	expectedErrMsg = ""
	if failureInfoErr.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, innerErr)
	}
}
