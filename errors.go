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

// CertificateNotFoundError is used when identified certificate is not found
// in the timestampe token
type CertificateNotFoundError error

// MalformedRequestError is used when timestamping request is malformed.
type MalformedRequestError struct {
	Msg string
}

// Error returns error message.
func (e MalformedRequestError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "malformed timestamping request"
}

// SignedTokenVerificationError is used when fail to verify signed token.
type SignedTokenVerificationError struct {
	Msg    string
	Detail error
}

// Error returns error message.
func (e SignedTokenVerificationError) Error() string {
	msg := "failed to verify signed token"
	if e.Msg != "" {
		msg += ": " + e.Msg
	}
	if e.Detail != nil {
		msg += ": " + e.Detail.Error()
	}
	return msg
}

// Unwrap returns the internal error.
func (e SignedTokenVerificationError) Unwrap() error {
	return e.Detail
}
