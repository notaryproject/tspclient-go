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
	"math/big"

	"github.com/notaryproject/tspclient-go/internal/hashutil"
	"github.com/notaryproject/tspclient-go/internal/oid"
)

// MessageImprint contains the hash of the datum to be time-stamped.
//
//	MessageImprint ::= SEQUENCE {
//	 hashAlgorithm   AlgorithmIdentifier,
//	 hashedMessage   OCTET STRING }
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// Request is a time-stamping request.
//
//	TimeStampReq ::= SEQUENCE {
//	 version         INTEGER                 { v1(1) },
//	 messageImprint  MessageImprint,
//	 reqPolicy       TSAPolicyID              OPTIONAL,
//	 nonce           INTEGER                  OPTIONAL,
//	 certReq         BOOLEAN                  DEFAULT FALSE,
//	 extensions      [0] IMPLICIT Extensions  OPTIONAL }
type Request struct {
	Version        int // fixed to 1 as defined in RFC 3161 2.4.1 Request Format
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"optional,tag:0"`
}

// RequestOptions provides options for user to create a new timestamp request
type RequestOptions struct {
	// Content is the datum to be time stamped. REQUIRED.
	Content []byte

	// HashAlgorithm is the hash algorithm to be used to hash the Content.
	// REQUIRED and MUST be an available hash algorithm.
	HashAlgorithm crypto.Hash

	// HashAlgorithmParameters is the parameters for the HashAlgorithm.
	// OPTIONAL.
	HashAlgorithmParameters asn1.RawValue

	// ReqPolicy specifies the TSA policy ID. OPTIONAL.
	ReqPolicy asn1.ObjectIdentifier

	// Nonce is a large random number with a high probability that the client
	// generates it only once. The same nonce is included and validated in the
	// response. OPTIONAL.
	Nonce *big.Int

	// CertReq determines if TSA signing certificate is included in the response.
	// OPTIONAL.
	CertReq bool

	// Extensions is a generic way to add additional information
	// to the request in the future. OPTIONAL.
	Extensions []pkix.Extension
}

// NewRequest creates a timestamp request based on user provided options.
func NewRequest(opts RequestOptions) (*Request, error) {
	if opts.Content == nil {
		return nil, &MalformedRequestError{Msg: "content to be time stamped cannot be empty"}
	}
	hashAlg, err := oid.FromHash(opts.HashAlgorithm)
	if err != nil {
		return nil, &MalformedRequestError{Msg: err.Error()}
	}
	digest, err := hashutil.ComputeHash(opts.HashAlgorithm, opts.Content)
	if err != nil {
		return nil, &MalformedRequestError{Msg: err.Error()}
	}
	return &Request{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  hashAlg,
				Parameters: opts.HashAlgorithmParameters,
			},
			HashedMessage: digest,
		},
		ReqPolicy:  opts.ReqPolicy,
		Nonce:      opts.Nonce,
		CertReq:    opts.CertReq,
		Extensions: opts.Extensions,
	}, nil
}

// MarshalBinary encodes the request to binary form.
// This method implements encoding.BinaryMarshaler.
//
// Reference: https://pkg.go.dev/encoding#BinaryMarshaler
func (r *Request) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil request")
	}
	return asn1.Marshal(*r)
}

// UnmarshalBinary decodes the request from binary form.
// This method implements encoding.BinaryUnmarshaler.
//
// Reference: https://pkg.go.dev/encoding#BinaryUnmarshaler
func (r *Request) UnmarshalBinary(data []byte) error {
	_, err := asn1.Unmarshal(data, r)
	return err
}

// Validate checks if req is a valid request against RFC 3161.
// It is used before a timstamp requestor sending the request to TSA.
func (req *Request) Validate() error {
	if req == nil {
		return &MalformedRequestError{Msg: "request cannot be nil"}
	}
	if req.Version != 1 {
		return &MalformedRequestError{Msg: fmt.Sprintf("request version must be 1, but got %d", req.Version)}
	}
	hashAlg := req.MessageImprint.HashAlgorithm.Algorithm
	hash, available := oid.ToHash(hashAlg)
	if !available {
		return &MalformedRequestError{Msg: fmt.Sprintf("hash algorithm %v is unavailable", hashAlg)}
	}
	if hash.Size() != len(req.MessageImprint.HashedMessage) {
		return &MalformedRequestError{Msg: fmt.Sprintf("hashed message is of incorrect size %d", len(req.MessageImprint.HashedMessage))}
	}
	return nil
}
