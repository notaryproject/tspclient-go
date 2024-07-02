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
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/notaryproject/tspclient-go/pki"
)

// signingCertificateV2 contains certificate hash and identifier of the
// TSA signing certificate.
//
// Reference: RFC 5035 3 signingCertificateV2
//
//	signingCertificateV2 ::=  SEQUENCE {
//	 certs        SEQUENCE OF ESSCertIDv2,
//	 policies     SEQUENCE OF PolicyInformation OPTIONAL }
type signingCertificateV2 struct {
	// Certificates contains the list of certificates. The first certificate
	// MUST be the signing certificate used to verify the timestamp token.
	Certificates []eSSCertIDv2

	// Policies suggests policy values to be used in the certification path
	// validation.
	Policies asn1.RawValue `asn1:"optional"`
}

// eSSCertIDv2 uniquely identifies a certificate.
//
// Reference: RFC 5035 4
//
//	eSSCertIDv2 ::=  SEQUENCE {
//	 hashAlgorithm           AlgorithmIdentifier
//	 	DEFAULT {algorithm id-sha256},
//	 certHash                 Hash,
//	 issuerSerial             IssuerSerial OPTIONAL }
type eSSCertIDv2 struct {
	// HashAlgorithm is the hashing algorithm used to hash certificate.
	// When it is not present, the default value is SHA256 (id-sha256).
	// Supported values are SHA256, SHA384, and SHA512
	HashAlgorithm pkix.AlgorithmIdentifier `asn1:"optional"`

	// CertHash is the certificate hash using algorithm specified
	// by HashAlgorithm. It is computed over the entire DER-encoded
	// certificate (including the signature)
	CertHash []byte

	// IssuerSerial holds the issuer and serialNumber of the certificate.
	// When it is not present, the SignerIdentifier field in the SignerInfo
	// will be used.
	IssuerSerial issuerAndSerial `asn1:"optional"`
}

// issuerAndSerial holds the issuer name and serialNumber of the certificate
//
// Reference: RFC 5035 4
//
//	IssuerSerial ::= SEQUENCE {
//		issuer                   GeneralNames,
//		serialNumber             CertificateSerialNumber }
type issuerAndSerial struct {
	IssuerName   generalNames
	SerialNumber *big.Int
}

// generalNames holds the issuer name of the certificate.
//
// Reference: RFC 3280 4.2.1.7
//
// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
//
//	GeneralName ::= CHOICE {
//		otherName                       [0]     OtherName,
//		rfc822Name                      [1]     IA5String,
//		dNSName                         [2]     IA5String,
//		x400Address                     [3]     ORAddress,
//		directoryName                   [4]     Name,
//		ediPartyName                    [5]     EDIPartyName,
//		uniformResourceIdentifier       [6]     IA5String,
//		iPAddress                       [7]     OCTET STRING,
//		registeredID                    [8]     OBJECT IDENTIFIER }
type generalNames struct {
	Name asn1.RawValue `asn1:"optional,tag:4"`
}

// Response is a time-stamping response.
//
//	TimeStampResp ::= SEQUENCE {
//	 status          PKIStatusInfo,
//	 timeStampToken  TimeStampToken  OPTIONAL }
type Response struct {
	Status         pki.StatusInfo
	TimestampToken asn1.RawValue `asn1:"optional"`
}

// MarshalBinary encodes the response to binary form.
// This method implements encoding.BinaryMarshaler.
//
// Reference: https://pkg.go.dev/encoding#BinaryMarshaler
func (r *Response) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil response")
	}
	return asn1.Marshal(*r)
}

// UnmarshalBinary decodes the response from binary form.
// This method implements encoding.BinaryUnmarshaler.
//
// Reference: https://pkg.go.dev/encoding#BinaryUnmarshaler
func (r *Response) UnmarshalBinary(data []byte) error {
	_, err := asn1.Unmarshal(data, r)
	return err
}

// SignedToken returns the timestamp token with signatures.
//
// Callers should invoke SignedToken.Verify to verify the content before
// comsumption.
func (r *Response) SignedToken() (*SignedToken, error) {
	if err := r.validateStatus(); err != nil {
		return nil, err
	}
	return ParseSignedToken(r.TimestampToken.FullBytes)
}

// Validate checks if resp is a successful timestamp response against
// its corresponding request based on RFC 3161.
// It is used when a timestamp requestor receives the response from TSA.
func (r *Response) Validate(req *Request) error {
	if req == nil {
		return &InvalidResponseError{Msg: "missing corresponding request"}
	}
	if r == nil {
		return &InvalidResponseError{Msg: "response cannot be nil"}
	}
	if err := r.validateStatus(); err != nil {
		return err
	}
	token, err := r.SignedToken()
	if err != nil {
		return &InvalidResponseError{Detail: err}
	}
	info, err := token.Info()
	if err != nil {
		return &InvalidResponseError{Detail: err}
	}
	if info.Version != 1 {
		return &InvalidResponseError{Msg: fmt.Sprintf("timestamp token info version must be 1, but got %d", info.Version)}
	}
	// check policy
	if req.ReqPolicy != nil && !req.ReqPolicy.Equal(info.Policy) {
		return &InvalidResponseError{Msg: fmt.Sprintf("policy in response %v does not match policy in request %v", info.Policy, req.ReqPolicy)}
	}
	// check MessageImprint
	if !info.MessageImprint.Equal(req.MessageImprint) {
		return &InvalidResponseError{Msg: fmt.Sprintf("message imprint in response %+v does not match with request %+v", info.MessageImprint, req.MessageImprint)}
	}
	// check gen time to be UTC
	// reference: https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.2
	genTime := info.GenTime
	if genTime.Location() != time.UTC {
		return &InvalidResponseError{Msg: "TSTInfo genTime must be in UTC"}
	}
	// check nonce
	if req.Nonce != nil {
		responseNonce := info.Nonce
		if responseNonce == nil || responseNonce.Cmp(req.Nonce) != 0 {
			return &InvalidResponseError{Msg: fmt.Sprintf("nonce in response %s does not match nonce in request %s", responseNonce, req.Nonce)}
		}
	}
	// check certReq
	if req.CertReq {
		for _, signerInfo := range token.SignerInfos {
			if _, err := token.SigningCertificate(&signerInfo); err == nil {
				// found at least one signing certificate
				return nil
			}
		}
		// no signing certificate was found
		return &InvalidResponseError{Msg: "certReq is True in request, but did not find any TSA signing certificate in the response"}
	}
	if len(token.Certificates) != 0 {
		return &InvalidResponseError{Msg: "certReq is False in request, but certificates field is included in the response"}
	}
	return nil
}

// validateStatus validates the response.Status
//
// Reference: RFC 3161 2.4.2
func (r *Response) validateStatus() error {
	if err := r.Status.Err(); err != nil {
		return &InvalidResponseError{Detail: err}
	}
	return nil
}
