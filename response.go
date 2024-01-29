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
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/notaryproject/tspclient-go/pki"
)

// Response is a time-stamping response.
//
//	TimeStampResp ::= SEQUENCE {
//	 status          PKIStatusInfo,
//	 timeStampToken  TimeStampToken  OPTIONAL }
type Response struct {
	Status         pki.StatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// SigningCertificateV2 contains certificate hash and identifier of the
// TSA signing certificate.
//
// Reference: RFC 5035 3 SigningCertificateV2
//
//	SigningCertificateV2 ::=  SEQUENCE {
//	 certs        SEQUENCE OF ESSCertIDv2,
//	 policies     SEQUENCE OF PolicyInformation OPTIONAL }
type SigningCertificateV2 struct {
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

// ValidateStatus validates the response.Status
//
// Reference: RFC 3161 2.4.2
func (r *Response) ValidateStatus() error {
	if r.Status.Status != pki.StatusGranted && r.Status.Status != pki.StatusGrantedWithMods {
		failureInfo, err := r.Status.ParseFailInfo()
		if err != nil {
			return fmt.Errorf("invalid response with status code %d: %s", r.Status.Status, r.Status.Status.String())
		}
		return fmt.Errorf("invalid response with status code %d: %s. Failure info: %s", r.Status.Status, r.Status.Status.String(), failureInfo)
	}
	return nil
}

// SignedToken returns the timestamp token with signatures.
// Callers should invoke Verify to verify the content before comsumption.
func (r *Response) SignedToken() (*SignedToken, error) {
	if err := r.ValidateStatus(); err != nil {
		return nil, err
	}
	return ParseSignedToken(context.Background(), r.TimeStampToken.FullBytes)
}
