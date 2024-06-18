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

package pki

import (
	"encoding/asn1"
	"testing"
)

// statuses is an array of supported PKIStatus
var statuses = []Status{
	StatusGranted,
	StatusGrantedWithMods,
	StatusRejection,
	StatusWaiting,
	StatusRevocationWarning,
	StatusRevocationNotification,
}

func TestStatusInfo(t *testing.T) {
	statusInfo := StatusInfo{
		Status: StatusGranted,
	}
	err := statusInfo.Err()
	if err != nil {
		t.Fatalf("expected nil error, but got %s", err)
	}

	statusInfo = StatusInfo{
		Status: StatusRejection,
		FailInfo: asn1.BitString{
			// unknown FailureInfo
			Bytes:     []byte{0x01},
			BitLength: 1,
		},
	}
	err = statusInfo.Err()
	expectedErrMsg := "invalid response with status code 2: rejected"
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
	}

	statusInfo = StatusInfo{
		Status: StatusRejection,
		FailInfo: asn1.BitString{
			// FailureInfoBadAlg
			Bytes:     []byte{0x80},
			BitLength: 1,
		},
	}
	err = statusInfo.Err()
	expectedErrMsg = "invalid response with status code 2: rejected. Failure info: unrecognized or unsupported Algorithm Identifier"
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
	}

	statusInfo = StatusInfo{
		Status: StatusRejection,
		FailInfo: asn1.BitString{
			// FailureInfoBadRequest and FailureInfoBadDataFormat
			Bytes:     []byte{0x24},
			BitLength: 8,
		},
	}
	err = statusInfo.Err()
	expectedErrMsg = "invalid response with status code 2: rejected. Failure info: transaction not permitted or supported; the data submitted has the wrong format"
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
	}
}

func TestStatusString(t *testing.T) {
	testData := []string{
		"granted",
		"granted with modifications",
		"rejected",
		"the request body part has not yet been processed, expect to hear more later",
		"warning: a revocation is imminent",
		"a revocation has occurred",
	}
	for idx, s := range statuses {
		if s.String() != testData[idx] {
			t.Fatalf("expected %s, but got %s", s.String(), testData[idx])
		}
	}

	unknown := Status(6)
	if unknown.String() != "unknown PKIStatus 6" {
		t.Fatalf("expected %s, but got %s", "unknown PKIStatus", unknown.String())
	}
}
