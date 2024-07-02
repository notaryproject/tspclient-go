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

// Package tspclient generates timestamping requests to TSA servers,
// fetches and verifies the responses according to RFC 3161 and RFC 5816
package tspclient

import "context"

// Timestamper stamps the time.
type Timestamper interface {
	// Timestamp stamps the time with the given request.
	Timestamp(context.Context, *Request) (*Response, error)
}
