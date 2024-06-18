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

import "strings"

// FailureInfoError is error of FailureInfo with a joined internal error
type FailureInfoError struct {
	// Detail is the joined internal error
	Detail error
}

// Error prints out the internal error e.Detail split by '; '
func (e *FailureInfoError) Error() string {
	if e.Detail == nil {
		return ""
	}
	return strings.ReplaceAll(e.Detail.Error(), "\n", "; ")
}

// Unwrap returns the internal error
func (e *FailureInfoError) Unwrap() error {
	return e.Detail
}
