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

// Package oid collects object identifiers for crypto algorithms.
package oid

import "encoding/asn1"

// OIDs for hash algorithms
var (
	// SHA256 (id-sha256) is defined in RFC 8017 B.1 Hash Functions
	SHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	// SHA384 (id-sha384) is defined in RFC 8017 B.1 Hash Functions
	SHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}

	// SHA512 (id-sha512) is defined in RFC 8017 B.1 Hash Functions
	SHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// OIDs for signature algorithms
var (
	// RSA is defined in RFC 8017 C ASN.1 Module
	RSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

	// SHA256WithRSA is defined in RFC 8017 C ASN.1 Module
	SHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}

	// SHA384WithRSA is defined in RFC 8017 C ASN.1 Module
	SHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}

	// SHA512WithRSA is defined in RFC 8017 C ASN.1 Module
	SHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}

	// RSAPSS is defined in RFC 8017 C ASN.1 Module
	RSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}

	// ECDSAWithSHA256 is defined in RFC 5758 3.2 ECDSA Signature Algorithm
	ECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

	// ECDSAWithSHA384 is defined in RFC 5758 3.2 ECDSA Signature Algorithm
	ECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}

	// ECDSAWithSHA512 is defined in RFC 5758 3.2 ECDSA Signature Algorithm
	ECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// OIDs defined in RFC 5652 Cryptographic Message Syntax (CMS)
var (
	// Data (id-data) is defined in RFC 5652 4 Data Content Type
	Data = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	// SignedData (id-signedData) is defined in RFC 5652 5.1 SignedData Type
	SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// ContentType (id-ct-contentType) is defined in RFC 5652 3 General Syntax
	ContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}

	// MessageDigest (id-messageDigest) is defined in RFC 5652 11.2 Message Digest
	MessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	// SigningTime (id-signingTime) is defined in RFC 5652 11.3 Signing Time
	SigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

// OIDs for RFC 3161 Timestamping
var (
	// TSTInfo (id-ct-TSTInfo) is defined in RFC 3161 2.4.2 Response Format
	TSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	// SigningCertificateV2 (id-aa-signingCertificate) is defined in RFC 2634 5.4
	//
	// Reference: https://datatracker.ietf.org/doc/html/rfc2634#section-5.4
	SigningCertificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}

	// SigningCertificateV2 (id-aa-signingCertificateV2) is defined in RFC 5035 3
	//
	// Reference: https://datatracker.ietf.org/doc/html/rfc5035#section-3
	SigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

	// ExtKeyUsage (id-ce-extKeyUsage) is defined in RFC 5280
	//
	// Reference: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12
	ExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

	// TimeStamping (id-kp-timeStamping) is defined in RFC 3161 2.3
	//
	// Reference: https://datatracker.ietf.org/doc/html/rfc3161#section-2.3
	TimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
)
