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
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/notaryproject/tspclient-go/internal/cms"
)

var rootCertPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIICyTCCAbGgAwIBAgIJAMKoxLbsiLVFMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNV\n" +
	"BAMMBFJvb3QwIBcNMjIwNjMwMTkyMDAyWhgPMjEyMjA2MDYxOTIwMDJaMA8xDTAL\n" +
	"BgNVBAMMBFJvb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC79rff\n" +
	"wcHY1g4Y3V89m8wmT9O5EuWzv2CXMRNuDHiAEzYtpCCZNXUzK2tDx0SMm7gSbL5R\n" +
	"sygeug1xo6B5ItcpS3Jr65sFd8XO/F2g8PRGZH5eZEBF+dogOjP1QgpkHtAtWuZh\n" +
	"Lc4O9Le6uqLHRm2bFOnyiqSSa/DbXdTXMIabOgVIHHOrDRM+uBYkPqV2PtUnGiNx\n" +
	"mVSatO/Gd8AMJ3QjuGxiArrMGPn5H0NrhaESbioFET2uHx337KNpSXjYOvI4zqbn\n" +
	"/E5XQrXk7WFvrrVytSNvoZKe2C3Rkx++LlMo6mGjnV4LmKptHRGEn+G4BxhFfYSF\n" +
	"cg8i2f/DPUEksEyvAgMBAAGjJjAkMBIGA1UdEwEB/wQIMAYBAf8CAQIwDgYDVR0P\n" +
	"AQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4IBAQB15AV+zNYU9H6CP4kT15yUaxE1\n" +
	"X1z5vt5K7yC0KTQgEuwouyhjK74FtGb7DRz1Irmncx9Ev109CCWfQIasJw1NaHCC\n" +
	"+TB0y7CVet4nawFTVTt3rJoLm3AAAh5EY0cOxSfF+kBSWQAPzBwK4XeeF10fqZde\n" +
	"r5ArNp1mk1X1GQPWr+bFzuAhOfbyo1rtX3JhTi9aPrH056mIVfnnS/6+jjqOYpeJ\n" +
	"EE2d/AqAytdgXIWq0Y/x/wymXgVINK2NEs1ajRyLPc9uGopZZFKyteqSbIk5H1PM\n" +
	"iVADu+Kjj+JocaQ4vRFSmR+5DGnLdBkP+woioprEIYD42nn7vW0yAZcuLnmo\n" +
	"-----END CERTIFICATE-----"

var intermediateCertPem1 = "-----BEGIN CERTIFICATE-----\n" +
	"MIICyjCCAbKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARSb290\n" +
	"MCAXDTIyMDYzMDE5MjAwM1oYDzMwMjExMDMxMTkyMDAzWjAYMRYwFAYDVQQDDA1J\n" +
	"bnRlcm1lZGlhdGUxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1JTs\n" +
	"aiC/7+bho43kMVyHDwCsuocYp4PvYahB59NsKDR4QbrImU5ziaQ94D0DQqthe9pm\n" +
	"qOW0SxN/vSRJAZFELxacrB9hc1y4MjiDYaRSt/LVx7astylBV/QRpmxWSEqp0Avu\n" +
	"6nMJivIa1sD0WIEchizx6jG9BI5ULr9LbJICYvMgDalQR+0JGG+rKWnf1mPZyxEu\n" +
	"9zEh215LCg5K56P3W5kC8fKBXSdSgTqZAvHzp6u78qet9S8gARtOEfS03A/7y7MC\n" +
	"U0Sn2wdQyQdci0PBsR2sTZvUw179Cr93r5aRbb3I6jXgMWHAP2vvIndb9CM9ePyY\n" +
	"yEy4Je7oWVVfMQ3CWQIDAQABoyYwJDASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1Ud\n" +
	"DwEB/wQEAwICBDANBgkqhkiG9w0BAQsFAAOCAQEALR0apUQVbWGmagLUz4Y/bRsl\n" +
	"mY9EJJXCiLuSxVWd3offjZfQTlGkQkCAW9FOQnm7JhEtaaHF1+AEVLo56/Gsd/hk\n" +
	"sXsrBagYGi72jun7QTb6j7iZ3X9zanrP3SjdkpjVnqxRfH83diSh0r68Xruq1NSK\n" +
	"qhUy1V+KQaXF0SSEutPqdTCoXUyxyXohVLU78uqZX/jx9Nc1XDuW9AZd+hMsLdk8\n" +
	"qGJqHYFvj2vOHGMTeYk8dWgMBthQeL0wdsg2AvKtAvn6FQXCN7mKCWjpFTtYsU8v\n" +
	"NsesS9M/i+geJjR/8/DDT3RP7S100BtCMm4XfHfmKcjXVaBh5evQVqGsa6TKLw==\n" +
	"-----END CERTIFICATE-----"

var intermediateCertPem2 = "-----BEGIN CERTIFICATE-----\n" +
	"MIIC0zCCAbugAwIBAgIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1JbnRl\n" +
	"cm1lZGlhdGUxMCAXDTIyMDYzMDE5MjAwM1oYDzMwMjExMDMxMTkyMDAzWjAYMRYw\n" +
	"FAYDVQQDDA1JbnRlcm1lZGlhdGUyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n" +
	"CgKCAQEAxH57OcIDpmuHgZ3y78HpyfNHVy0JwIpIp1quSBN5SHRkzouh+LcuVjic\n" +
	"/1DGwiut312XeIyKoeOLcNnsY1qfZgxtFxJCfZSArnyoHb6O0vRvUq/yY1cjOZea\n" +
	"J4U/ZsSPEt4S5oFApWLGFH6c7sRNmh3bPcPDsm1gNd+gM/UCSyCH62gmRn3r5nKA\n" +
	"4fkwrs46tBGDs+bwwj5/AupJETX4P+NaFE7XcAJP6ShMAGa/ykunyEvDsc8tdzhD\n" +
	"zvoyWRxMjrTZlAu+5THbz4ZgRZja2noQDGoV5g9QMzebLbAS/+YY+OJfGHtA0li8\n" +
	"THw5ZzButCmk+Us49FlN0MlyDC4oNwIDAQABoyYwJDASBgNVHRMBAf8ECDAGAQH/\n" +
	"AgEAMA4GA1UdDwEB/wQEAwICBDANBgkqhkiG9w0BAQsFAAOCAQEADbd56yUDfUCQ\n" +
	"pahXOS0OYBJ9GB+PRdp6lkvZTNPfu5cynZwla1juZFee71w+fcppSzpecGu8esLO\n" +
	"h9+1RooWKGqJpLoAvvUJMW6kZsGBTPjpSeH6xUP9HwxfWrZwg3FMMGMIzOs90jCZ\n" +
	"47U6CevxAGTtkvO8QMIQOx9VNcUDjX1utlkyCdAHccZLq2gw9wWHSfZWydKXpJVP\n" +
	"ffDPsF4LkjJb7XHFB8KOxYjvyomLXGTNlni1hRxadSKrRX9xeAztIZ1ReFgYVRQn\n" +
	"8TwCIeaN4N2TNJWeVmBSnYU7iuay6A/qkauuG2+Hc7eL834IzRejYpecoCjBwQFT\n" +
	"6OInMQCKnA==\n" +
	"-----END CERTIFICATE-----"

var codeSigningLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIC5DCCAcygAwIBAgIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1JbnRl\n" +
	"cm1lZGlhdGUyMCAXDTIyMDYzMDE5MjAwM1oYDzMwMjExMDMxMTkyMDAzWjAaMRgw\n" +
	"FgYDVQQDDA9Db2RlU2lnbmluZ0xlYWYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
	"ggEKAoIBAQCfySlwm2lF1eMP8RZVjG1PAp6wJiqNfI1m4Oll5jZFBDPLFqUJFG2i\n" +
	"Zun5GecxJD8mz56AxB95vohQd1+AkPXE7bCpN085hQm3jMbbdg0N0HS+cAATGUDR\n" +
	"VEi/laHLSs8myuG9enJ1/EIGli8hZnOeSW46RaHtlawPbIXa8/8yV1McmrQjOOqj\n" +
	"K+m1Rra2J3apyqUL37K6MrydoLIy/ldvuGbfMDrsRZVu6GbtNMyV+6qwc91NL0aa\n" +
	"g67ge3LaQ4VcLXFSCYpbNzBMl+xBYGLFS4EgNe3VT0HOfOwYn7hcwRF7I0jmUBgH\n" +
	"BTP2yGYKuobDMslaK+FHisptT/qn29ihAgMBAAGjNTAzMA4GA1UdDwEB/wQEAwIH\n" +
	"gDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA0GCSqGSIb3DQEB\n" +
	"CwUAA4IBAQB8BAQTnqDkm4K4l0W6a26gl+usPmKzOsrFuKCbeAjUuNMOEcnignO0\n" +
	"URPXvXBEbQGMyNNmS7ix7JjU4BqbM4KSFfIXrCWvdHZTicWl+1+84HVktwmW2bIg\n" +
	"xJPo+m1ZLAsRLnBFmf27p7QBYVCYUvNKvbAqgP9rOPtTOkHe2WtiVNAGxDvWBdKr\n" +
	"gHcqUwRA3v7VfmW9EDoxLvkI9R0HolbiYQzp7GmA+KT5L/CMd50+2fUGaUnaacrU\n" +
	"v8kypIYx5OTOGTYisidXueUhhbp6RZYvpiQuX+O/bkIjSPMf+oXgbDcpRe18XeK4\n" +
	"cwtsQn/iENuvFcfRHcFhvRjEFrIP+Ugx\n" +
	"-----END CERTIFICATE-----"

var invalidPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIC5DCCAcygAwIBAgIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1JbnRl\n" +
	"cm1lZGlhdGUyMCAXDTIyMDYzMDE5MjAwM1oYDzMwMjExMDMxMTkyMDAzWjAaMRgw\n" +
	"FgYDVQQDDA9Db2RlU2lnbmluZ0xlYWYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
	"v8kypIYx5OTOGTYisidXueUhhbp6RZYvpiQuX+O/bkIjSPMf+oXgbDcpRe18XeK4\n" +
	"cwtsQn/iENuvFcfRHcFhvRjEFrIP+Ugx\n" +
	"-----END CERTIFICATE-----"

var rootCert = parseCertificateFromString(rootCertPem)
var intermediateCert1 = parseCertificateFromString(intermediateCertPem1)
var intermediateCert2 = parseCertificateFromString(intermediateCertPem2)
var codeSigningCert = parseCertificateFromString(codeSigningLeafPem)

func TestSetupRootCertPool(t *testing.T) {
	data, err := os.ReadFile("testdata/TimestampToken.p7s")
	if err != nil {
		t.Fatal("failed to read timestamp token:", err)
	}
	signed, err := cms.ParseSignedData(data)
	if err != nil {
		t.Fatal("failed to parse signed data:", err)
	}
	certs := signed.Certificates

	roots, err := SetupRootCertPool(certs)
	if err != nil {
		t.Fatalf("expected nil error, but got %s", err.Error())
	}
	if roots == nil {
		t.Fatal("expected non-nil root cert pool")
	}

	var noRootCerts []*x509.Certificate
	for _, cert := range certs {
		if !isRoot(cert) {
			noRootCerts = append(noRootCerts, cert)
		}
	}
	expectedErrMsg := "cannot retrieve any tsa root certificate"
	_, err = SetupRootCertPool(noRootCerts)
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err.Error())
	}

	data, err = os.ReadFile("testdata/TimestampTokenNoRoot.p7s")
	if err != nil {
		t.Fatal("failed to read timestamp token:", err)
	}
	signed, err = cms.ParseSignedData(data)
	if err != nil {
		t.Fatal("failed to parse signed data:", err)
	}
	certsWithoutRoot := signed.Certificates

	roots, err = SetupRootCertPool(certsWithoutRoot)
	if err != nil {
		t.Fatalf("expected nil error, but got %s", err.Error())
	}
	if roots == nil {
		t.Fatal("expected non-nil root cert pool")
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()
	for idx := range certsWithoutRoot {
		certsWithoutRoot[idx].IssuingCertificateURL = []string{ts.URL}
	}
	_, err = SetupRootCertPool(certsWithoutRoot)
	expectedErrMsg = "https response bad status: 403 Forbidden"
	if err == nil || !strings.Contains(err.Error(), expectedErrMsg) {
		t.Fatalf("expected error message to contain %s, but got %s", expectedErrMsg, err.Error())
	}

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("notation")); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer ts.Close()
	MaxRootCertBytes = 0
	certsWithoutRoot = signed.Certificates
	for idx := range certsWithoutRoot {
		certsWithoutRoot[idx].IssuingCertificateURL = []string{ts.URL}
	}
	_, err = SetupRootCertPool(certsWithoutRoot)
	expectedErrMsg = "https response reached the 0 KiB size limit"
	if err == nil || !strings.Contains(err.Error(), expectedErrMsg) {
		t.Fatalf("expected error message to contain %s, but got %s", expectedErrMsg, err.Error())
	}

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		invalid, err := os.ReadFile("testdata/invalid.crt")
		if err != nil {
			t.Fatal("failed to read invalid.crt:", err)
		}
		if _, err := w.Write(invalid); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer ts.Close()
	MaxRootCertBytes = 100 * 1024
	certsWithoutRoot = signed.Certificates
	for idx := range certsWithoutRoot {
		certsWithoutRoot[idx].IssuingCertificateURL = []string{ts.URL}
	}
	_, err = SetupRootCertPool(certsWithoutRoot)
	expectedErrMsg = "x509: malformed certificate"
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err.Error())
	}

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	MaxRootCertBytes = 100 * 1024
	certsWithoutRoot = signed.Certificates
	for idx := range certsWithoutRoot {
		certsWithoutRoot[idx].IssuingCertificateURL = []string{ts.URL}
	}
	_, err = SetupRootCertPool(certsWithoutRoot)
	expectedErrMsg = "does not contain valid x509 certificate"
	if err == nil || !strings.Contains(err.Error(), expectedErrMsg) {
		t.Fatalf("expected error message to contain %s, but got %s", expectedErrMsg, err.Error())
	}
}

func TestIsRoot(t *testing.T) {
	selfSignedCodeSigning := isRoot(codeSigningCert)
	selfSignedIntermediateCert1 := isRoot(intermediateCert1)
	selfSignedIntermediateCert2 := isRoot(intermediateCert2)
	selfSignedRootCert := isRoot(rootCert)
	if selfSignedCodeSigning || selfSignedIntermediateCert1 ||
		selfSignedIntermediateCert2 || !selfSignedRootCert {
		t.Fatal("Root cert was not correctly identified")
	}
}

func TestParseCertificates(t *testing.T) {
	validPem := []byte(codeSigningLeafPem)
	_, err := parseCertificates(validPem)
	if err != nil {
		t.Fatal(err)
	}

	validDer, err := os.ReadFile("testdata/timestamp_root.crt")
	if err != nil {
		t.Fatal("failed to read timestamp_root.crt:", err)
	}
	_, err = parseCertificates(validDer)
	if err != nil {
		t.Fatal(err)
	}

	invalidPemBytes := []byte(invalidPem)
	_, err = parseCertificates(invalidPemBytes)
	expectedErrMsg := "x509: malformed certificate"
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
	}

	invalid, err := os.ReadFile("testdata/invalid.crt")
	if err != nil {
		t.Fatal("failed to read invalid.crt:", err)
	}
	_, err = parseCertificates(invalid)
	expectedErrMsg = "x509: malformed certificate"
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
	}
}

func parseCertificateFromString(certPem string) *x509.Certificate {
	stringAsBytes := []byte(certPem)
	cert, _ := parseCertificates(stringAsBytes)
	return cert[0]
}
