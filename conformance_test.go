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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/notaryproject/tspclient-go/internal/cms"
	"github.com/notaryproject/tspclient-go/internal/hashutil"
	"github.com/notaryproject/tspclient-go/internal/oid"
	"github.com/notaryproject/tspclient-go/pki"
)

// responseRejection is a general response for request rejection.
var responseRejection = &Response{
	Status: pki.StatusInfo{
		Status: pki.StatusRejection,
	},
}

var (
	// sha1WithRSA is defined in RFC 8017 C ASN.1 Module; bad algorithm,
	// for testing purpose only
	sha1WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
)

// testTSA is a Timestamping Authority for testing purpose.
type testTSA struct {
	// key is the TSA signing key.
	key *rsa.PrivateKey

	// cert is the self-signed certificate by the TSA signing key.
	cert *x509.Certificate

	// nowFunc provides the current time. time.Now() is used if nil.
	nowFunc func() time.Time
}

func TestTSATimestampGranted(t *testing.T) {
	// prepare TSA
	now := time.Date(2021, 9, 18, 11, 54, 34, 0, time.UTC)
	tsa, err := newTestTSA(false, true)
	if err != nil {
		t.Fatalf("NewTSA() error = %v", err)
	}
	tsa.nowFunc = func() time.Time {
		return now
	}

	// do timestamp
	message := []byte("notation")
	requestOpts := RequestOptions{
		Content:       message,
		HashAlgorithm: crypto.SHA256,
		CertReq:       true,
	}
	req, err := NewRequest(requestOpts)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	ctx := context.Background()
	resp, err := tsa.Timestamp(ctx, req)
	if err != nil {
		t.Fatalf("TSA.Timestamp() error = %v", err)
	}
	wantStatus := pki.StatusGranted
	if got := resp.Status.Status; got != wantStatus {
		t.Fatalf("Response.Status = %v, want %v", got, wantStatus)
	}

	// verify timestamp token
	token, err := resp.SignedToken()
	if err != nil {
		t.Fatalf("Response.SignedToken() error = %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(tsa.certificate())
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := token.Verify(context.Background(), opts); err != nil {
		t.Fatal("SignedToken.Verify() error =", err)
	}
	info, err := token.Info()
	if err != nil {
		t.Fatal("SignedToken.Info() error =", err)
	}
	ts, accuracy, err := info.Timestamp(message)
	if err != nil {
		t.Errorf("TSTInfo.Timestamp() error = %v", err)
	}
	wantTimestamp := now
	if ts != wantTimestamp {
		t.Errorf("TSTInfo.Timestamp() Timestamp = %v, want %v", ts, wantTimestamp)
	}
	wantAccuracy := time.Second
	if accuracy != wantAccuracy {
		t.Errorf("TSTInfo.Timestamp() Accuracy = %v, want %v", accuracy, wantAccuracy)
	}
}

func TestTSATimestampRejection(t *testing.T) {
	// prepare TSA
	tsa, err := newTestTSA(false, true)
	if err != nil {
		t.Fatalf("NewTSA() error = %v", err)
	}

	// do timestamp
	requestOpts := RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
		CertReq:       true,
	}
	req, err := NewRequest(requestOpts)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.MessageImprint.HashAlgorithm.Algorithm = sha1WithRSA // set bad algorithm
	ctx := context.Background()
	resp, err := tsa.Timestamp(ctx, req)
	if err != nil {
		t.Fatalf("TSA.Timestamp() error = %v", err)
	}
	wantStatus := pki.StatusRejection
	if got := resp.Status.Status; got != wantStatus {
		t.Fatalf("Response.Status = %v, want %v", got, wantStatus)
	}
}

func TestTSATimestampMalformedExtKeyUsage(t *testing.T) {
	// prepare TSA
	now := time.Date(2021, 9, 18, 11, 54, 34, 0, time.UTC)
	tsa, err := newTestTSA(true, false)
	if err != nil {
		t.Fatalf("NewTSA() error = %v", err)
	}
	tsa.nowFunc = func() time.Time {
		return now
	}

	// do timestamp
	requestOpts := RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
		CertReq:       true,
	}
	req, err := NewRequest(requestOpts)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	ctx := context.Background()
	resp, err := tsa.Timestamp(ctx, req)
	if err != nil {
		t.Fatalf("TSA.Timestamp() error = %v", err)
	}
	wantStatus := pki.StatusGranted
	if got := resp.Status.Status; got != wantStatus {
		t.Fatalf("Response.Status = %v, want %v", got, wantStatus)
	}

	// verify timestamp token
	token, err := resp.SignedToken()
	if err != nil {
		t.Fatalf("Response.SignedToken() error = %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(tsa.certificate())
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	expectedErrMsg := "failed to verify signed token: signing certificate MUST have and only have ExtKeyUsageTimeStamping as extended key usage"
	if _, err := token.Verify(context.Background(), opts); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestTSATimestampNonCriticalExtKeyUsage(t *testing.T) {
	// prepare TSA
	now := time.Date(2021, 9, 18, 11, 54, 34, 0, time.UTC)
	tsa, err := newTestTSA(false, false)
	if err != nil {
		t.Fatalf("NewTSA() error = %v", err)
	}
	tsa.nowFunc = func() time.Time {
		return now
	}

	// do timestamp
	requestOpts := RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
		CertReq:       true,
	}
	req, err := NewRequest(requestOpts)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	ctx := context.Background()
	resp, err := tsa.Timestamp(ctx, req)
	if err != nil {
		t.Fatalf("TSA.Timestamp() error = %v", err)
	}
	wantStatus := pki.StatusGranted
	if got := resp.Status.Status; got != wantStatus {
		t.Fatalf("Response.Status = %v, want %v", got, wantStatus)
	}

	// verify timestamp token
	token, err := resp.SignedToken()
	if err != nil {
		t.Fatalf("Response.SignedToken() error = %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(tsa.certificate())
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	expectedErrMsg := "failed to verify signed token: signing certificate extended key usage extension MUST be set as critical"
	if _, err := token.Verify(context.Background(), opts); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestTSATimestampWithoutCertificate(t *testing.T) {
	// prepare TSA
	now := time.Date(2021, 9, 18, 11, 54, 34, 0, time.UTC)
	tsa, err := newTestTSA(false, true)
	if err != nil {
		t.Fatalf("NewTSA() error = %v", err)
	}
	tsa.nowFunc = func() time.Time {
		return now
	}

	// do timestamp
	message := []byte("notation")
	requestOpts := RequestOptions{
		Content:       message,
		HashAlgorithm: crypto.SHA256,
		CertReq:       false,
	}
	req, err := NewRequest(requestOpts)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	ctx := context.Background()
	resp, err := tsa.Timestamp(ctx, req)
	if err != nil {
		t.Fatalf("TSA.Timestamp() error = %v", err)
	}
	wantStatus := pki.StatusGranted
	if got := resp.Status.Status; got != wantStatus {
		t.Fatalf("Response.Status = %v, want %v", got, wantStatus)
	}

	// verify timestamp token
	token, err := resp.SignedToken()
	if err != nil {
		t.Fatalf("Response.SignedToken() error = %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(tsa.certificate())
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	expectedErrMsg := "failed to verify signed token: signing certificate not found in the timestamp token"
	_, err = token.Verify(context.Background(), opts)
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

// newTestTSA creates a testTSA with random credentials.
func newTestTSA(malformedExtKeyUsage, criticalTimestampingExtKeyUsage bool) (*testTSA, error) {
	// generate key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// generate certificate
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	var extKeyUsages []x509.ExtKeyUsage
	if malformedExtKeyUsage {
		extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageAny)
	} else {
		extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageTimeStamping)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "timestamp test",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           extKeyUsages,
		BasicConstraintsValid: true,
	}
	if criticalTimestampingExtKeyUsage {
		extValue, err := asn1.Marshal([]asn1.ObjectIdentifier{oid.TimeStamping})
		if err != nil {
			return nil, err
		}
		template.ExtraExtensions = []pkix.Extension{
			{
				Id:       oid.ExtKeyUsage,
				Critical: true,
				Value:    extValue,
			},
		}
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	return &testTSA{
		key:  key,
		cert: cert,
	}, nil
}

// certificate returns the certificate used by the server.
func (tsa *testTSA) certificate() *x509.Certificate {
	return tsa.cert
}

// Timestamp stamps the time with the given request.
func (tsa *testTSA) Timestamp(_ context.Context, req *Request) (*Response, error) {
	// validate request
	if req.Version != 1 {
		return responseRejection, nil
	}
	hash, ok := oid.ToHash(req.MessageImprint.HashAlgorithm.Algorithm)
	if !ok {
		return responseRejection, nil
	}
	if hashedMessage := req.MessageImprint.HashedMessage; len(hashedMessage) != hash.Size() {
		return responseRejection, nil
	}

	// generate token info
	policy := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4146, 2} // time-stamp-policies
	switch hash {
	case crypto.SHA1:
		policy = append(policy, 2)
	case crypto.SHA256, crypto.SHA384, crypto.SHA512:
		policy = append(policy, 3)
	default:
		return responseRejection, nil
	}
	infoBytes, err := tsa.generateTokenInfo(req, policy)
	if err != nil {
		return nil, err
	}

	// generate signed data
	signed, err := tsa.generateSignedData(infoBytes, req.CertReq)
	if err != nil {
		return nil, err
	}
	content, err := convertToRawASN1(signed, "explicit,tag:0")
	if err != nil {
		return nil, err
	}

	// generate content info
	contentInfo := cms.ContentInfo{
		ContentType: oid.SignedData,
		Content:     content,
	}
	token, err := convertToRawASN1(contentInfo, "")
	if err != nil {
		return nil, err
	}

	// generate response
	return &Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
		TimeStampToken: token,
	}, nil
}

// generateTokenInfo generate timestamp token info.
func (tsa *testTSA) generateTokenInfo(req *Request, policy asn1.ObjectIdentifier) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	nowFunc := tsa.nowFunc
	if nowFunc == nil {
		nowFunc = time.Now
	}
	info := TSTInfo{
		Version:        1,
		Policy:         policy,
		MessageImprint: req.MessageImprint,
		SerialNumber:   serialNumber,
		GenTime:        nowFunc().UTC().Truncate(time.Second),
		Accuracy: Accuracy{
			Seconds: 1,
		},
	}
	return asn1.Marshal(info)
}

// generateSignedData generate signed data according to
func (tsa *testTSA) generateSignedData(infoBytes []byte, requestCert bool) (cms.SignedData, error) {
	var issuer asn1.RawValue
	_, err := asn1.Unmarshal(tsa.cert.RawIssuer, &issuer)
	if err != nil {
		return cms.SignedData{}, err
	}
	contentType, err := convertToRawASN1([]interface{}{oid.TSTInfo}, "set")
	if err != nil {
		return cms.SignedData{}, err
	}
	infoDigest, err := hashutil.ComputeHash(crypto.SHA256, infoBytes)
	if err != nil {
		return cms.SignedData{}, err
	}
	messageDigest, err := convertToRawASN1([]interface{}{infoDigest}, "set")
	if err != nil {
		return cms.SignedData{}, err
	}
	signingTime, err := convertToRawASN1([]interface{}{time.Now().UTC()}, "set")
	if err != nil {
		return cms.SignedData{}, err
	}
	certHash, err := hashutil.ComputeHash(crypto.SHA256, tsa.cert.Raw)
	if err != nil {
		return cms.SignedData{}, err
	}
	signingCertificateV2 := signingCertificateV2{
		Certificates: []eSSCertIDv2{
			{
				CertHash: certHash,
			},
		},
	}
	signingCertificateV2Raw, err := convertToRawASN1([]interface{}{signingCertificateV2}, "set")
	if err != nil {
		return cms.SignedData{}, err
	}
	signed := cms.SignedData{
		Version: 3,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{
			{
				Algorithm: oid.SHA256,
			},
		},
		EncapsulatedContentInfo: cms.EncapsulatedContentInfo{
			ContentType: oid.TSTInfo,
			Content:     infoBytes,
		},
		SignerInfos: []cms.SignerInfo{
			{
				Version: 1,
				SignerIdentifier: cms.IssuerAndSerialNumber{
					Issuer:       issuer,
					SerialNumber: tsa.cert.SerialNumber,
				},
				DigestAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm: oid.SHA256,
				},
				SignedAttributes: cms.Attributes{
					{
						Type:   oid.ContentType,
						Values: contentType,
					},
					{
						Type:   oid.MessageDigest,
						Values: messageDigest,
					},
					{
						Type:   oid.SigningTime,
						Values: signingTime,
					},
					{
						Type:   oid.SigningCertificateV2,
						Values: signingCertificateV2Raw,
					},
				},
				SignatureAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm: oid.SHA256WithRSA,
				},
			},
		},
	}
	if requestCert {
		certs, err := convertToRawASN1(tsa.cert.Raw, "tag:0")
		if err != nil {
			return cms.SignedData{}, err
		}
		signed.Certificates = certs
	}

	// sign data
	signer := &signed.SignerInfos[0]
	encodedAttributes, err := asn1.MarshalWithParams(signer.SignedAttributes, "set")
	if err != nil {
		return cms.SignedData{}, err
	}
	hashedAttributes, err := hashutil.ComputeHash(crypto.SHA256, encodedAttributes)
	if err != nil {
		return cms.SignedData{}, err
	}
	signer.Signature, err = rsa.SignPKCS1v15(rand.Reader, tsa.key, crypto.SHA256, hashedAttributes)
	if err != nil {
		return cms.SignedData{}, err
	}
	return signed, nil
}

// convertToRawASN1 convert any data ASN.1 data structure to asn1.RawValue.
func convertToRawASN1(val interface{}, params string) (asn1.RawValue, error) {
	b, err := asn1.MarshalWithParams(val, params)
	if err != nil {
		return asn1.NullRawValue, err
	}
	var raw asn1.RawValue
	_, err = asn1.UnmarshalWithParams(b, &raw, params)
	if err != nil {
		return asn1.NullRawValue, err
	}
	return raw, nil
}
