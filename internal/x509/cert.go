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

package x509

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	set "github.com/notaryproject/tspclient-go/internal/container"
)

// MaxRootCertBytes specifies the limit on how many bytes are allowed in the
// response to download root certificate from intermediate certificate issuer
// URL.
//
// The root certificate size must be strictly less than this value.
var MaxRootCertBytes int64 = 100 * 1024 // 100 KiB

// DownloadCertFromURLTimeout is the timeout when downloading cert from a
// URL
const DownloadCertFromURLTimeout = 30 * time.Second

// SetupRootCertPool sets up a root certificate pool for tsa certificate chain
// building. If root certificate already included in the tsa timestamp token,
// then directly use it. Otherwise, download the root cert from intermediate
// cert's IssuingCertificateURL. An error would be returned if none of the above
// methods could get the tsa root cert.
func SetupRootCertPool(certs []*x509.Certificate) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	subjectSet := set.New[string]()
	var foundRoot bool
	// check if any root cert is already in the tsa response
	for _, cert := range certs {
		subjectSet.Add(cert.Subject.String())
		if isRoot(cert) {
			// found root cert
			foundRoot = true
			roots.AddCert(cert)
		}
	}
	if !foundRoot { // check if can download valid root cert from URL
		client := &http.Client{Timeout: DownloadCertFromURLTimeout}
		for _, cert := range certs {
			// cert's issuer is not in the tsa response, and cert has a
			// non-empty IssuingCertificateURL
			if !subjectSet.Contains(cert.Issuer.String()) && len(cert.IssuingCertificateURL) > 0 {
				req, err := http.NewRequest(http.MethodGet, cert.IssuingCertificateURL[0], nil)
				if err != nil {
					return nil, err
				}
				resp, err := client.Do(req)
				if err != nil {
					return nil, err
				}
				defer resp.Body.Close()
				// Check server response
				if resp.StatusCode != http.StatusOK {
					return nil, fmt.Errorf("%s %q: https response bad status: %s", resp.Request.Method, resp.Request.URL, resp.Status)
				}
				lr := &io.LimitedReader{
					R: resp.Body,
					N: MaxRootCertBytes,
				}
				certBytes, err := io.ReadAll(lr)
				if err != nil {
					return nil, err
				}
				if lr.N == 0 {
					return nil, fmt.Errorf("%s %q: https response reached the %d KiB size limit", resp.Request.Method, resp.Request.URL, MaxRootCertBytes/1024)
				}
				certs, err := parseCertificates(certBytes)
				if err != nil {
					return nil, err
				}
				if len(certs) == 0 {
					return nil, fmt.Errorf("%s %q: does not contain valid x509 certificate", resp.Request.Method, resp.Request.URL)
				}
				if isRoot(certs[0]) {
					// found root cert
					foundRoot = true
					roots.AddCert(certs[0])
					break
				}
			}
		}
	}
	if !foundRoot {
		return nil, errors.New("cannot retrieve any tsa root certificate")
	}
	return roots, nil
}

// isRoot returns true if cert is a root certificate
func isRoot(cert *x509.Certificate) bool {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return false
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return false
	}
	return bytes.Equal(cert.RawSubject, cert.RawIssuer)
}

// parseCertificates parses certificates from either PEM or DER data
// returns an empty list if no certificates are found
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	block, rest := pem.Decode(data)
	if block == nil {
		// data may be in DER format
		derCerts, err := x509.ParseCertificates(data)
		if err != nil {
			return nil, err
		}
		certs = append(certs, derCerts...)
	} else {
		// data is in PEM format
		for block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
			block, rest = pem.Decode(rest)
		}
	}
	return certs, nil
}
