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
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/notaryproject/tspclient-go/internal/cms"
	"github.com/notaryproject/tspclient-go/internal/hashutil"
	"github.com/notaryproject/tspclient-go/internal/oid"
)

// SignedToken is a parsed timestamp token with signatures.
type SignedToken cms.ParsedSignedData

// ParseSignedToken parses ASN.1 BER-encoded structure to SignedToken
// without verification.
// Callers should invoke Verify to verify the content before comsumption.
func ParseSignedToken(ctx context.Context, berData []byte) (*SignedToken, error) {
	signed, err := cms.ParseSignedData(berData)
	if err != nil {
		return nil, err
	}
	if !oid.TSTInfo.Equal(signed.ContentType) {
		return nil, fmt.Errorf("unexpected content type: %v", signed.ContentType)
	}
	return (*SignedToken)(signed), nil
}

// Verify verifies the signed token as CMS SignedData.
// An empty list of KeyUsages in VerifyOptions implies ExtKeyUsageTimeStamping.
// The `Intermediates` in the verify options will be ignored and
// re-contrusted using the certificates in the parsed signed token.
// It returns success when the first signer info verification succeeds.
func (t *SignedToken) Verify(ctx context.Context, opts x509.VerifyOptions) ([]*x509.Certificate, error) {
	if len(t.SignerInfos) == 0 {
		return nil, SignedTokenVerificationError{Msg: "signerInfo not found"}
	}
	if len(opts.KeyUsages) == 0 {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	}
	intermediates := x509.NewCertPool()
	for _, cert := range t.Certificates {
		intermediates.AddCert(cert)
	}
	opts.Intermediates = intermediates
	signed := (*cms.ParsedSignedData)(t)
	var lastErr error
	for _, signerInfo := range t.SignerInfos {
		signingCertificate, err := t.GetSigningCertificate(&signerInfo)
		if err != nil {
			lastErr = SignedTokenVerificationError{Detail: err}
			continue
		}
		certChain, err := signed.VerifySigner(ctx, &signerInfo, signingCertificate, opts)
		if err != nil {
			lastErr = SignedTokenVerificationError{Detail: err}
			continue
		}
		// RFC 3161 2.3: The corresponding certificate MUST contain only one
		// instance of the extended key usage field extension.
		if len(signingCertificate.ExtKeyUsage) == 1 &&
			signingCertificate.ExtKeyUsage[0] == x509.ExtKeyUsageTimeStamping &&
			len(signingCertificate.UnknownExtKeyUsage) == 0 {
			return certChain, nil
		} else {
			lastErr = SignedTokenVerificationError{Msg: "signing certificate MUST only have ExtKeyUsageTimeStamping as extended key usage"}
		}
	}
	return nil, lastErr
}

// Info returns the timestamping information. Caller MUST validate the timestamp
// token info before consumption.
func (t *SignedToken) Info() (*TSTInfo, error) {
	var info TSTInfo
	if _, err := asn1.Unmarshal(t.Content, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// GetSigningCertificate gets the signing certificate identified by SignedToken
// SignerInfo's SigningCertificate or SigningCertificateV2 attribute.
// If the IssuerSerial field of signing certificate is missing,
// use signerInfo's sid instead.
// The identified signing certificate MUST match the hash in SigningCertificate
// or SigningCertificateV2.
// When both are present, SigningCertificateV2 is used because it uses hash
// algorithm beyond SHA1. If both are missing, an error will be returned.
//
// References: RFC 3161 2.4.1 & 2.4.2; RFC 5816; RFC 5035 4; RFC 2634 5.4
func (t *SignedToken) GetSigningCertificate(signerInfo *cms.SignerInfo) (*x509.Certificate, error) {
	var signingCertificate signingCertificate
	var useSigningCertificate bool
	var signingCertificateV2 signingCertificateV2
	if err := signerInfo.SignedAttributes.TryGet(oid.SigningCertificateV2, &signingCertificateV2); err != nil {
		if !errors.Is(err, cms.ErrAttributeNotFound) {
			return nil, fmt.Errorf("failed to get SigningCertificateV2 from signed attributes: %w", err)
		}
		// signingCertificateV2 is missing, use signingCertificate instead
		useSigningCertificate = true
		if err := signerInfo.SignedAttributes.TryGet(oid.SigningCertificate, &signingCertificate); err != nil {
			if !errors.Is(err, cms.ErrAttributeNotFound) {
				return nil, fmt.Errorf("failed to get SigningCertificate from signed attributes: %w", err)
			}
			// signingCertificate is missing as well
			return nil, errors.New("invalid timestamp token: both signingCertificate and signingCertificateV2 fields are missing")
		}
	}
	// get candidate signing certificate
	var candidateSigningCert *x509.Certificate
	var issuerSerial issuerAndSerial
	if useSigningCertificate {
		if len(signingCertificate.Certificates) == 0 {
			return nil, errors.New("signingCertificate does not contain any certificate")
		}
		issuerSerial = signingCertificate.Certificates[0].IssuerSerial
	} else {
		if len(signingCertificateV2.Certificates) == 0 {
			return nil, errors.New("signingCertificateV2 does not contain any certificate")
		}
		issuerSerial = signingCertificateV2.Certificates[0].IssuerSerial
	}
	signed := (*cms.ParsedSignedData)(t)
	if issuerSerial.SerialNumber != nil {
		// use IssuerSerial from signed attribute
		if issuerSerial.IssuerName.Name.Bytes == nil {
			return nil, errors.New("issuer name is missing in IssuerSerial")
		}
		var issuer asn1.RawValue
		if _, err := asn1.Unmarshal(issuerSerial.IssuerName.Name.Bytes, &issuer); err != nil {
			return nil, fmt.Errorf("failed to unmarshal issuer name: %w", err)
		}
		ref := cms.IssuerAndSerialNumber{
			Issuer:       issuer,
			SerialNumber: issuerSerial.SerialNumber,
		}
		candidateSigningCert = signed.GetCertificate(ref)
	} else {
		// use sid (unsigned) as IssuerSerial
		candidateSigningCert = signed.GetCertificate(signerInfo.SignerIdentifier)
	}
	if candidateSigningCert == nil {
		return nil, CertificateNotFoundError(errors.New("signing certificate not found in the timestamp token"))
	}
	// validate hash of candidate signing certificate
	var hashFunc crypto.Hash
	var expectedCertHash []byte
	if useSigningCertificate {
		hashFunc = crypto.SHA1
		expectedCertHash = signingCertificate.Certificates[0].CertHash
	} else {
		hashFunc = crypto.SHA256 // default hash algorithm for signingCertificateV2 is id-sha256
		var ok bool
		if signingCertificateV2.Certificates[0].HashAlgorithm.Algorithm != nil {
			// use hash algorithm from SigningCertificateV2 signed attribute
			hashFunc, ok = oid.ToHash(signingCertificateV2.Certificates[0].HashAlgorithm.Algorithm)
			if !ok {
				return nil, errors.New("unsupported certificate hash algorithm in SigningCertificateV2 attribute")
			}
		}
		expectedCertHash = signingCertificateV2.Certificates[0].CertHash
	}
	certHash, err := hashutil.ComputeHash(hashFunc, candidateSigningCert.Raw)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(certHash, expectedCertHash) {
		return nil, errors.New("signing certificate hash does not match CertHash in signed attribute")
	}
	return candidateSigningCert, nil
}

//	Accuracy ::= SEQUENCE {
//	 seconds     INTEGER             OPTIONAL,
//	 millis  [0] INTEGER (1..999)    OPTIONAL,
//	 micros  [1] INTEGER (1..999)    OPTIONAL }
type Accuracy struct {
	Seconds      int `asn1:"optional"`
	Milliseconds int `asn1:"optional,tag:0"`
	Microseconds int `asn1:"optional,tag:1"`
}

//	TSTInfo ::= SEQUENCE {
//	 version         INTEGER                 { v1(1) },
//	 policy          TSAPolicyId,
//	 messageImprint  MessageImprint,
//	 serialNumber    INTEGER,
//	 genTime         GeneralizedTime,
//	 accuracy        Accuracy                OPTIONAL,
//	 ordering        BOOLEAN                 DEFAULT FALSE,
//	 nonce           INTEGER                 OPTIONAL,
//	 tsa             [0] GeneralName         OPTIONAL,
//	 extensions      [1] IMPLICIT Extensions OPTIONAL }
type TSTInfo struct {
	Version        int // fixed to 1 as defined in RFC 3161 2.4.2
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       Accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

// Timestamp returns the timestamp by TSA and its accuracy.
// tst MUST be valid and the time stamped datum MUST match message.
func (tst *TSTInfo) Timestamp(message []byte) (time.Time, time.Duration, error) {
	if err := tst.Validate(message); err != nil {
		return time.Time{}, 0, err
	}
	accuracy := time.Duration(tst.Accuracy.Seconds)*time.Second +
		time.Duration(tst.Accuracy.Milliseconds)*time.Millisecond +
		time.Duration(tst.Accuracy.Microseconds)*time.Microsecond
	return tst.GenTime, accuracy, nil
}

// Validate checks tst against RFC 3161.
// message is verified against the timestamp token MessageImprint.
func (tst *TSTInfo) Validate(message []byte) error {
	if tst == nil {
		return &TSTInfoError{Msg: "timestamp token info cannot be nil"}
	}
	if tst.Version != 1 {
		return &TSTInfoError{Msg: fmt.Sprintf("timestamp token info version must be 1, but got %d", tst.Version)}
	}
	hashAlg := tst.MessageImprint.HashAlgorithm.Algorithm
	hash, ok := oid.ToHash(hashAlg)
	if !ok {
		return &TSTInfoError{Msg: fmt.Sprintf("unrecognized hash algorithm: %v", hashAlg)}
	}
	messageDigest, err := hashutil.ComputeHash(hash, message)
	if err != nil {
		return &TSTInfoError{Detail: err}
	}
	if !bytes.Equal(tst.MessageImprint.HashedMessage, messageDigest) {
		return &TSTInfoError{Msg: "mismatched message"}
	}
	return nil
}
