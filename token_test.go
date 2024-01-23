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
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	"github.com/notaryproject/tspclient-go/internal/hashutil"
	"github.com/notaryproject/tspclient-go/internal/oid"
)

func TestParseSignedToken(t *testing.T) {
	timestampToken, err := os.ReadFile("testdata/TimeStampTokenWithInvalideContentType.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg := fmt.Sprintf("unexpected content type: %v", oid.Data)
	_, err = ParseSignedToken(context.Background(), timestampToken)
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestVerify(t *testing.T) {
	timestampToken, err := getTimestampTokenFromPath("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	rootCABytes, err := os.ReadFile("testdata/GlobalSignRootCA.crt")
	if err != nil {
		t.Fatal("failed to read root CA certificate:", err)
	}
	if ok := roots.AppendCertsFromPEM(rootCABytes); !ok {
		t.Fatal("failed to load root CA certificate")
	}
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := timestampToken.Verify(context.Background(), opts); err != nil {
		t.Fatalf("expected nil error, but got %v", err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithValidAndInvalidSignerInfos.p7s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := timestampToken.Verify(context.Background(), opts); err != nil {
		t.Fatalf("expected nil error, but got %v", err)
	}

	timestampToken = &SignedToken{}
	expectedErrMsg := "failed to verify signed token: signerInfo not found"
	if _, err := timestampToken.Verify(context.Background(), opts); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithoutCertificate.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "failed to verify signed token: signing certificate not found in the timestamp token"
	if _, err := timestampToken.Verify(context.Background(), opts); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithInvalidSignature.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "failed to verify signed token: cms: verification failure: crypto/rsa: verification error"
	if _, err := timestampToken.Verify(context.Background(), opts); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestInfo(t *testing.T) {
	timestampToken, err := getTimestampTokenFromPath("testdata/TimeStampTokenWithInvalidTSTInfo.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg := "asn1: structure error: tags don't match (23 vs {class:0 tag:16 length:3 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:24 set:false omitEmpty:false} Time @89"
	if _, err := timestampToken.Info(); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithTSTInfoVersion2.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "timestamp token info version must be 1, but got 2"
	if _, err := timestampToken.Info(); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestGetSigningCertificate(t *testing.T) {
	timestampToken, err := getTimestampTokenFromPath("testdata/TimeStampTokenWithoutSigningCertificateV2.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg := "failed to get SigningCertificateV2 from signed attributes: attribute not found"
	if _, err := timestampToken.GetSigningCertificate(context.Background(), &timestampToken.SignerInfos[0]); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithWrongSigningCertificateV2IssuerChoiceTag.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "issuer name is missing in IssuerSerial of SigningCertificateV2 attribute"
	if _, err := timestampToken.GetSigningCertificate(context.Background(), &timestampToken.SignerInfos[0]); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithoutSigningCertificateV2IssuerSerial.p7s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := timestampToken.GetSigningCertificate(context.Background(), &timestampToken.SignerInfos[0]); err != nil {
		t.Fatalf("expected nil error, but got %v", err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithoutCertificate.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "signing certificate not found in the timestamp token"
	if _, err := timestampToken.GetSigningCertificate(context.Background(), &timestampToken.SignerInfos[0]); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithSHA1CertHash.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "unsupported certificate hash algorithm in SigningCertificateV2 attribute"
	if _, err := timestampToken.GetSigningCertificate(context.Background(), &timestampToken.SignerInfos[0]); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithMismatchCertHash.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "signing certificate hash does not match CertHash in SigningCertificateV2 attribute"
	if _, err := timestampToken.GetSigningCertificate(context.Background(), &timestampToken.SignerInfos[0]); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestVerifyContent(t *testing.T) {
	message := []byte("notation")
	timestampToken, err := getTimestampTokenFromPath("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal(err)
	}
	tstInfo, err := timestampToken.Info()
	if err != nil {
		t.Fatal(err)
	}
	if err := tstInfo.VerifyContent(message); err != nil {
		t.Fatalf("expected nil error, but got %v", err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/SHA1TimeStampToken.p7s")
	if err != nil {
		t.Fatal(err)
	}
	tstInfo, err = timestampToken.Info()
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg := "unrecognized hash algorithm: 1.2.840.113549.1.1.5"
	if err := tstInfo.VerifyContent(message); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestTSTInfoVerify(t *testing.T) {
	timestampToken, err := getTimestampTokenFromPath("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal(err)
	}
	tstInfo, err := timestampToken.Info()
	if err != nil {
		t.Fatal(err)
	}
	messageDigest, err := hashutil.ComputeHash(crypto.SHA256, []byte("notation"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tstInfo.Verify(messageDigest); err != nil {
		t.Fatalf("expected nil error, but got %v", err)
	}

	messageDigest = []byte("invalid")
	expectedErrMsg := "mismatch message digest"
	if err := tstInfo.Verify(messageDigest); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func getTimestampTokenFromPath(path string) (*SignedToken, error) {
	timestampToken, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseSignedToken(context.Background(), timestampToken)
}
