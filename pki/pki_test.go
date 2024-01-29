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
	"errors"
	"testing"
)

func TestParseFailInfo(t *testing.T) {
	statusInfo := StatusInfo{
		Status: StatusGranted,
	}
	_, err := statusInfo.ParseFailInfo()
	if !errors.Is(err, ErrUnknownFailureInfo) {
		t.Fatalf("error should be ErrUnknownFailureInfo, but got %s", err)
	}

	statusInfo = StatusInfo{
		Status: StatusRejection,
		FailInfo: asn1.BitString{
			Bytes:     []byte{0x01},
			BitLength: 1,
		},
	}
	_, err = statusInfo.ParseFailInfo()
	if !errors.Is(err, ErrUnknownFailureInfo) {
		t.Fatalf("error should be ErrUnknownFailureInfo, but got %s", err)
	}

	statusInfo = StatusInfo{
		Status: StatusRejection,
		FailInfo: asn1.BitString{
			Bytes:     []byte{0x80},
			BitLength: 1,
		},
	}
	failInfo, err := statusInfo.ParseFailInfo()
	if err != nil || failInfo != FailureInfoBadAlg {
		t.Fatalf("expected %v, but got %v", FailureInfoBadAlg, failInfo)
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
	for idx, s := range Statuses {
		if s.String() != testData[idx] {
			t.Fatalf("expected %s, but got %s", s.String(), testData[idx])
		}
	}

	unknown := Status(6)
	if unknown.String() != "unknown PKIStatus" {
		t.Fatalf("expected %s, but got %s", "unknown PKIStatus", unknown.String())
	}
}

func TestFailureInfoString(t *testing.T) {
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
	for idx, f := range FailureInfos {
		if f.String() != testData[idx] {
			t.Fatalf("expected %s, but got %s", f.String(), testData[idx])
		}
	}

	unknown := FailureInfo(1)
	if unknown.String() != "unknown PKIFailureInfo" {
		t.Fatalf("expected %s, but got %s", "unknown PKIFailureInfo", unknown.String())
	}
}
