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
	"fmt"
	"time"
)

// Timestamp denotes the time at which the timestamp token was created by the TSA
//
// Reference: RFC 3161 2.4.2
type Timestamp struct {
	// Value is the GenTime of TSTInfo
	Value time.Time

	// Accuracy is the Accuracy of TSTInfo
	Accuracy time.Duration
}

// BoundedBefore returns true if the upper limit of the time at which the
// timestamp token was created is before or equal to u.
//
// Reference: RFC 3161 2.4.2
func (t *Timestamp) BoundedBefore(u time.Time) bool {
	timestampUpperLimit := t.Value.Add(t.Accuracy)
	return timestampUpperLimit.Before(u) || timestampUpperLimit.Equal(u)
}

// BoundedAfter returns true if the lower limit of the time at which the
// timestamp token was created is after or equal to u.
//
// Reference: RFC 3161 2.4.2
func (t *Timestamp) BoundedAfter(u time.Time) bool {
	timestampLowerLimit := t.Value.Add(-t.Accuracy)
	return timestampLowerLimit.After(u) || timestampLowerLimit.Equal(u)
}

// String returns a string of t as a timestamp range calculated with its accuracy.
func (t *Timestamp) String() string {
	return fmt.Sprintf("timestamp range: [%v, %v]", t.Value.Add(-t.Accuracy), t.Value.Add(t.Accuracy))
}
