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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	tspclientasn1 "github.com/notaryproject/tspclient-go/internal/encoding/asn1"
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

// Equal compares if m and n are the same MessageImprint
//
// Reference: RFC 3161 2.4.2
func (m MessageImprint) Equal(n MessageImprint) bool {
	return m.HashAlgorithm.Algorithm.Equal(n.HashAlgorithm.Algorithm) &&
		tspclientasn1.EqualRawValue(m.HashAlgorithm.Parameters, n.HashAlgorithm.Parameters) &&
		bytes.Equal(m.HashedMessage, n.HashedMessage)
}

// asn1NullRawValue represents the valid struct of asn1.NullRawValue
//
// https://pkg.go.dev/encoding/asn1#NullRawValue
var asn1NullRawValue = asn1.RawValue{
	Tag:       asn1.TagNull,
	FullBytes: []byte{asn1.TagNull, 0},
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

// RequestOptions provides options for caller to create a new timestamp request
type RequestOptions struct {
	// Content is the datum to be time stamped. REQUIRED.
	Content []byte

	// HashAlgorithm is the hash algorithm to be used to hash the Content.
	// REQUIRED and MUST be an available hash algorithm.
	HashAlgorithm crypto.Hash

	// HashAlgorithmParameters is the parameters for the HashAlgorithm.
	// OPTIONAL.
	//
	// Reference: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.2
	HashAlgorithmParameters asn1.RawValue

	// ReqPolicy specifies the TSA policy ID. OPTIONAL.
	//
	// Reference: https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.1
	ReqPolicy asn1.ObjectIdentifier

	// NoNonce disables any Nonce usage. When set to true, the Nonce field is
	// ignored, and no built-in Nonce will be generated. OPTIONAL.
	NoNonce bool

	// Nonce is a large random number with a high probability that the client
	// generates it only once. The same nonce is included and validated in the
	// response. It is only used when NoNonce is not set to true.
	//
	// When this field is nil, a built-in Nonce will be generated and sent to
	// the TSA. OPTIONAL.
	Nonce *big.Int

	// NoCert tells the TSA to not include any signing certificate in its
	// response. By default, TSA signing certificate is included in the response.
	// OPTIONAL.
	NoCert bool

	// Extensions is a generic way to add additional information
	// to the request in the future. OPTIONAL.
	Extensions []pkix.Extension
}

// NewRequest creates a timestamp request based on caller provided options.
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
	hashAlgParameter := opts.HashAlgorithmParameters
	if tspclientasn1.EqualRawValue(hashAlgParameter, asn1.RawValue{}) || tspclientasn1.EqualRawValue(hashAlgParameter, asn1.NullRawValue) {
		hashAlgParameter = asn1NullRawValue
	}
	var nonce *big.Int
	if !opts.NoNonce {
		if opts.Nonce != nil { // user provided Nonce, use it
			nonce = opts.Nonce
		} else { // user ignored Nonce, use built-in Nonce
			var err error
			nonce, err = generateNonce()
			if err != nil {
				return nil, &MalformedRequestError{Msg: err.Error()}
			}
		}
	}
	return &Request{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  hashAlg,
				Parameters: hashAlgParameter,
			},
			HashedMessage: digest,
		},
		ReqPolicy:  opts.ReqPolicy,
		Nonce:      nonce,
		CertReq:    !opts.NoCert,
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

// generateNonce generates a built-in Nonce for TSA request
func generateNonce() (*big.Int, error) {
	// Pick a random number from 0 to 2^159
	nonce, err := rand.Int(rand.Reader, (&big.Int{}).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, errors.New("error generating nonce")
	}
	return nonce, nil
}
