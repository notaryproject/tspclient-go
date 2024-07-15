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
	"testing"
	"time"
)

func TestTimestamp(t *testing.T) {
	// timestamp range:
	// [time.Date(2021, time.September, 17, 14, 9, 8, 0, time.UTC),
	//  time.Date(2021, time.September, 17, 14, 9, 12, 0, time.UTC)]
	timestamp := Timestamp{
		Value:    time.Date(2021, time.September, 17, 14, 9, 10, 0, time.UTC),
		Accuracy: 2 * time.Second,
	}
	u1 := time.Date(2021, time.September, 17, 14, 9, 7, 0, time.UTC)
	u2 := time.Date(2021, time.September, 17, 14, 9, 8, 0, time.UTC)
	u3 := time.Date(2021, time.September, 17, 14, 9, 9, 0, time.UTC)
	u4 := time.Date(2021, time.September, 17, 14, 9, 10, 0, time.UTC)
	u5 := time.Date(2021, time.September, 17, 14, 9, 11, 0, time.UTC)
	u6 := time.Date(2021, time.September, 17, 14, 9, 12, 0, time.UTC)
	u7 := time.Date(2021, time.September, 17, 14, 9, 13, 0, time.UTC)

	if timestamp.BoundedBefore(u1) {
		t.Fatal("timestamp.BoundedBefore expected false, but got true")
	}
	if !timestamp.BoundedAfter(u1) {
		t.Fatal("timestamp.BoundedAfter expected true, but got false")
	}

	if timestamp.BoundedBefore(u2) {
		t.Fatal("timestamp.BoundedBefore expected false, but got true")
	}
	if !timestamp.BoundedAfter(u2) {
		t.Fatal("timestamp.BoundedAfter expected true, but got false")
	}

	if timestamp.BoundedBefore(u3) {
		t.Fatal("timestamp.BoundedBefore expected false, but got true")
	}
	if timestamp.BoundedAfter(u3) {
		t.Fatal("timestamp.BoundedAfter expected false, but got true")
	}

	if timestamp.BoundedBefore(u4) {
		t.Fatal("timestamp.BoundedBefore expected false, but got true")
	}
	if timestamp.BoundedAfter(u4) {
		t.Fatal("timestamp.BoundedAfter expected false, but got true")
	}

	if timestamp.BoundedBefore(u5) {
		t.Fatal("timestamp.BoundedBefore expected false, but got true")
	}
	if timestamp.BoundedAfter(u5) {
		t.Fatal("timestamp.BoundedAfter expected false, but got true")
	}

	if !timestamp.BoundedBefore(u6) {
		t.Fatal("timestamp.BoundedBefore expected true, but got false")
	}
	if timestamp.BoundedAfter(u6) {
		t.Fatal("timestamp.BoundedAfter expected false, but got true")
	}

	if !timestamp.BoundedBefore(u7) {
		t.Fatal("timestamp.BoundedBefore expected true, but got false")
	}
	if timestamp.BoundedAfter(u7) {
		t.Fatal("timestamp.BoundedAfter expected false, but got true")
	}
}

func TestString(t *testing.T) {
	// timestamp range:
	// [time.Date(2021, time.September, 17, 14, 9, 8, 0, time.UTC),
	//  time.Date(2021, time.September, 17, 14, 9, 12, 0, time.UTC)]
	timestamp := Timestamp{
		Value:    time.Date(2021, time.September, 17, 14, 9, 10, 0, time.UTC),
		Accuracy: 2 * time.Second,
	}

	expectedStr := "[2021-09-17T14:09:08Z, 2021-09-17T14:09:12Z]"
	if timestamp.Format(time.RFC3339) != expectedStr {
		t.Fatalf("expected %s, but got %s", expectedStr, timestamp.Format(time.RFC3339))
	}
}
