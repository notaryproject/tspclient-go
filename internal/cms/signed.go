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

package cms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/notaryproject/tspclient-go/internal/encoding/asn1/ber"
	"github.com/notaryproject/tspclient-go/internal/hashutil"
	"github.com/notaryproject/tspclient-go/internal/oid"
)

// ParsedSignedData is a parsed SignedData structure for golang friendly types.
type ParsedSignedData struct {
	// Content is the content of the EncapsulatedContentInfo.
	Content []byte

	// ContentType is the content type of the EncapsulatedContentInfo.
	ContentType asn1.ObjectIdentifier

	// Certificates is the list of certificates in the SignedData.
	Certificates []*x509.Certificate

	// CRLs is the list of certificate revocation lists in the SignedData.
	CRLs []x509.RevocationList

	// SignerInfos is the list of signer information in the SignedData.
	SignerInfos []SignerInfo
}

// ParseSignedData parses ASN.1 BER-encoded SignedData structure to golang
// friendly types.
//
// Only supported SignedData version is 3.
func ParseSignedData(berData []byte) (*ParsedSignedData, error) {
	data, err := ber.ConvertToDER(berData)
	if err != nil {
		return nil, SyntaxError{Message: "invalid signed data: failed to convert from BER to DER", Detail: err}
	}
	var contentInfo ContentInfo
	if _, err := asn1.Unmarshal(data, &contentInfo); err != nil {
		return nil, SyntaxError{Message: "invalid content info: failed to unmarshal DER to ContentInfo", Detail: err}
	}
	if !oid.SignedData.Equal(contentInfo.ContentType) {
		return nil, ErrNotSignedData
	}

	var signedData SignedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, SyntaxError{Message: "invalid signed data", Detail: err}
	}

	if signedData.Version != 3 {
		return nil, SyntaxError{Message: fmt.Sprintf("unsupported signed data version: got %d, want 3", signedData.Version)}
	}

	certs, err := x509.ParseCertificates(signedData.Certificates.Bytes)
	if err != nil {
		return nil, SyntaxError{Message: "failed to parse X.509 certificates from signed data. Only X.509 certificates are supported", Detail: err}
	}

	return &ParsedSignedData{
		Content:      signedData.EncapsulatedContentInfo.Content,
		ContentType:  signedData.EncapsulatedContentInfo.ContentType,
		Certificates: certs,
		CRLs:         signedData.CRLs,
		SignerInfos:  signedData.SignerInfos,
	}, nil
}

// Verify attempts to verify the content in the parsed signed data against the signer
// information. The `Intermediates` in the verify options will be ignored and
// re-contrusted using the certificates in the parsed signed data.
// If more than one signature is present, the successful validation of any signature
// implies that the content in the parsed signed data is valid.
// On successful verification, the list of signing certificates that successfully
// verify is returned.
// If all signatures fail to verify, the last error is returned.
//
// References:
//   - RFC 5652 5   Signed-data Content Type
//   - RFC 5652 5.4 Message Digest Calculation Process
//   - RFC 5652 5.6 Signature Verification Process
//
// WARNING: this function doesn't do any revocation checking.
func (d *ParsedSignedData) Verify(ctx context.Context, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	if len(d.SignerInfos) == 0 {
		return nil, ErrSignerInfoNotFound
	}
	if len(d.Certificates) == 0 {
		return nil, ErrCertificateNotFound
	}

	intermediates := x509.NewCertPool()
	for _, cert := range d.Certificates {
		intermediates.AddCert(cert)
	}
	opts.Intermediates = intermediates
	verifiedSignerMap := map[string][]*x509.Certificate{}
	var lastErr error
	for _, signerInfo := range d.SignerInfos {
		signingCertificate := d.GetCertificate(signerInfo.SignerIdentifier)
		if signingCertificate == nil {
			lastErr = ErrCertificateNotFound
			continue
		}

		certChain, err := d.VerifySigner(ctx, &signerInfo, signingCertificate, opts)
		if err != nil {
			lastErr = err
			continue
		}

		thumbprint, err := hashutil.ComputeHash(crypto.SHA256, signingCertificate.Raw)
		if err != nil {
			lastErr = err
			continue
		}
		verifiedSignerMap[hex.EncodeToString(thumbprint)] = certChain
	}
	if len(verifiedSignerMap) == 0 {
		return nil, lastErr
	}

	verifiedSigningCertChains := make([][]*x509.Certificate, 0, len(verifiedSignerMap))
	for _, certChain := range verifiedSignerMap {
		verifiedSigningCertChains = append(verifiedSigningCertChains, certChain)
	}
	return verifiedSigningCertChains, nil
}

// VerifySigner verifies the signerInfo against the user specified signingCertificate.
//
// This function should be used when:
//
// 1. The certificates field of d is missing. This function allows the caller to provide
// a signing certificate to verify the signerInfo.
//
// 2. The caller doesn't trust the signer identifier (unsigned field) of signerInfo
// to identify signing certificate. This function allows such caller to use their trusted
// signing certificate.
//
// Note: the intermediate certificates (if any) and root certificates in the verify
// options MUST be set by the caller. The certificates field of d is not used in this function.
//
// References:
//   - RFC 5652 5   Signed-data Content Type
//   - RFC 5652 5.4 Message Digest Calculation Process
//   - RFC 5652 5.6 Signature Verification Process
//
// WARNING: this function doesn't do any revocation checking.
func (d *ParsedSignedData) VerifySigner(ctx context.Context, signerInfo *SignerInfo, signingCertificate *x509.Certificate, opts x509.VerifyOptions) ([]*x509.Certificate, error) {
	if signerInfo == nil {
		return nil, VerificationError{Message: "VerifySigner failed: signer info is required"}
	}

	if signingCertificate == nil {
		return nil, VerificationError{Message: "VerifySigner failed: signing certificate is required"}
	}

	if signerInfo.Version != 1 {
		// Only IssuerAndSerialNumber is supported currently
		return nil, VerificationError{Message: fmt.Sprintf("invalid signer info version: only version 1 is supported; got %d", signerInfo.Version)}
	}

	return d.verify(signerInfo, signingCertificate, &opts)
}

// verify verifies the trust in a top-down manner.
//
// References:
//   - RFC 5652 5.4 Message Digest Calculation Process
//   - RFC 5652 5.6 Signature Verification Process
func (d *ParsedSignedData) verify(signerInfo *SignerInfo, cert *x509.Certificate, opts *x509.VerifyOptions) ([]*x509.Certificate, error) {
	// verify signer certificate
	certChains, err := cert.Verify(*opts)
	if err != nil {
		return nil, VerificationError{Detail: err}
	}

	// verify signature
	if err := d.verifySignature(signerInfo, cert); err != nil {
		return nil, err
	}

	// verify attribute
	return d.verifySignedAttributes(signerInfo, certChains)
}

// verifySignature verifies the signature with a trusted certificate.
//
// References:
//   - RFC 5652 5.4 Message Digest Calculation Process
//   - RFC 5652 5.6 Signature Verification Process
func (d *ParsedSignedData) verifySignature(signerInfo *SignerInfo, cert *x509.Certificate) error {
	// verify signature
	algorithm := oid.ToSignatureAlgorithm(
		signerInfo.DigestAlgorithm.Algorithm,
		signerInfo.SignatureAlgorithm.Algorithm,
	)
	if algorithm == x509.UnknownSignatureAlgorithm {
		return VerificationError{Message: "unknown signature algorithm"}
	}

	signed := d.Content
	if len(signerInfo.SignedAttributes) > 0 {
		encoded, err := asn1.MarshalWithParams(signerInfo.SignedAttributes, "set")
		if err != nil {
			return VerificationError{Message: "invalid signed attributes", Detail: err}
		}
		signed = encoded
	}

	if err := cert.CheckSignature(algorithm, signed, signerInfo.Signature); err != nil {
		return VerificationError{Detail: err}
	}
	return nil
}

// verifySignedAttributes verifies the signed attributes.
//
// References:
//   - RFC 5652 5.3 SignerInfo Type
//   - RFC 5652 5.6 Signature Verification Process
func (d *ParsedSignedData) verifySignedAttributes(signerInfo *SignerInfo, chains [][]*x509.Certificate) ([]*x509.Certificate, error) {
	if len(chains) == 0 {
		return nil, VerificationError{Message: "Failed to verify signed attributes because the certificate chain is empty."}
	}

	// verify attributes if present
	if len(signerInfo.SignedAttributes) == 0 {
		// According to RFC 5652, if the Content Type is id-data, signed
		// attributes can be empty. However, this cms package is designed for
		// timestamp (RFC 3161) and the content type must be id-ct-TSTInfo,
		// so we require signed attributes to be present.
		return nil, VerificationError{Message: "missing signed attributes"}
	}

	// this CMS package is designed for timestamping (RFC 3161), so checking the
	// content type to be id-ct-TSTInfo is an optimization for tspclient to
	// fail fast.
	if !oid.TSTInfo.Equal(d.ContentType) {
		return nil, fmt.Errorf("unexpected content type: %v. Expected to be id-ct-TSTInfo (%v)", d.ContentType, oid.TSTInfo)
	}
	var contentType asn1.ObjectIdentifier
	if err := signerInfo.SignedAttributes.Get(oid.ContentType, &contentType); err != nil {
		return nil, VerificationError{Message: "invalid content type", Detail: err}
	}
	if !d.ContentType.Equal(contentType) {
		return nil, VerificationError{Message: fmt.Sprintf("mismatch content type: found %q in signer info, and %q in signed data", contentType, d.ContentType)}
	}

	var expectedDigest []byte
	if err := signerInfo.SignedAttributes.Get(oid.MessageDigest, &expectedDigest); err != nil {
		return nil, VerificationError{Message: "invalid message digest", Detail: err}
	}
	hash, ok := oid.ToHash(signerInfo.DigestAlgorithm.Algorithm)
	if !ok {
		return nil, VerificationError{Message: "unsupported digest algorithm"}
	}
	actualDigest, err := hashutil.ComputeHash(hash, d.Content)
	if err != nil {
		return nil, VerificationError{Message: "hash failure", Detail: err}
	}
	if !bytes.Equal(expectedDigest, actualDigest) {
		return nil, VerificationError{Message: "mismatch message digest"}
	}

	// sanity check on signing time
	var signingTime time.Time
	if err := signerInfo.SignedAttributes.Get(oid.SigningTime, &signingTime); err != nil {
		if errors.Is(err, ErrAttributeNotFound) {
			return chains[0], nil
		}
		return nil, VerificationError{Message: "invalid signing time", Detail: err}
	}

	// verify signing time is within the validity period of all certificates
	// in the chain. As long as one chain is valid, the signature is valid.
	for _, chain := range chains {
		if isSigningTimeValid(chain, signingTime) {
			return chain, nil
		}
	}

	return nil, VerificationError{Message: fmt.Sprintf("signing time, %s, is outside certificate's validity period", signingTime)}
}

// GetCertificate finds the certificate by issuer name and issuer-specific
// serial number.
// Reference: RFC 5652 5 Signed-data Content Type
func (d *ParsedSignedData) GetCertificate(ref IssuerAndSerialNumber) *x509.Certificate {
	for _, cert := range d.Certificates {
		if bytes.Equal(cert.RawIssuer, ref.Issuer.FullBytes) && cert.SerialNumber.Cmp(ref.SerialNumber) == 0 {
			return cert
		}
	}
	return nil
}

// isSigningTimeValid helpes to check if signingTime is within the validity
// period of all certificates in the chain
func isSigningTimeValid(chain []*x509.Certificate, signingTime time.Time) bool {
	for _, cert := range chain {
		if signingTime.Before(cert.NotBefore) || signingTime.After(cert.NotAfter) {
			return false
		}
	}
	return true
}
