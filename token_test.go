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
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/notaryproject/tspclient-go/internal/oid"
)

func TestParseSignedToken(t *testing.T) {
	timestampToken, err := os.ReadFile("testdata/TimeStampTokenWithInvalideContentType.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg := fmt.Sprintf("unexpected content type: %v", oid.Data)
	_, err = ParseSignedToken(timestampToken)
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
	expectedErrMsg = "failed to verify signed token: cms verification failure: crypto/rsa: verification error"
	if _, err := timestampToken.Verify(context.Background(), opts); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "failed to verify signed token: tsa root certificate pool cannot be nil"
	if _, err := timestampToken.Verify(context.Background(), x509.VerifyOptions{}); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
	}
}

func TestInfo(t *testing.T) {
	timestampToken, err := getTimestampTokenFromPath("testdata/TimeStampTokenWithInvalidTSTInfo.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg := "cannot unmarshal TSTInfo from timestamp token: asn1: structure error: tags don't match (23 vs {class:0 tag:16 length:3 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:24 set:false omitEmpty:false} Time @89"
	if _, err := timestampToken.Info(); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestGetSigningCertificate(t *testing.T) {
	timestampToken, err := getTimestampTokenFromPath("testdata/TimeStampTokenWithoutSigningCertificate.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg := "failed to get SigningCertificateV2 from signed attributes: attribute not found"
	if _, err := timestampToken.SigningCertificate(&timestampToken.SignerInfos[0]); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithWrongSigningCertificateV2IssuerChoiceTag.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "issuer name is missing in IssuerSerial"
	if _, err := timestampToken.SigningCertificate(&timestampToken.SignerInfos[0]); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithoutSigningCertificateV2IssuerSerial.p7s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := timestampToken.SigningCertificate(&timestampToken.SignerInfos[0]); err != nil {
		t.Fatalf("expected nil error, but got %v", err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithoutCertificate.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "signing certificate not found in the timestamp token"
	if _, err := timestampToken.SigningCertificate(&timestampToken.SignerInfos[0]); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithSHA1CertHash.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "unsupported certificate hash algorithm in SigningCertificateV2 attribute"
	if _, err := timestampToken.SigningCertificate(&timestampToken.SignerInfos[0]); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithMismatchCertHash.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "signing certificate hash does not match CertHash in signed attribute"
	if _, err := timestampToken.SigningCertificate(&timestampToken.SignerInfos[0]); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithInvalidSigningCertificateV2.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "failed to get SigningCertificateV2 from signed attributes: asn1: syntax error: sequence truncated"
	if _, err := timestampToken.SigningCertificate(&timestampToken.SignerInfos[0]); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithSigningCertificateV2NoCert.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "signingCertificateV2 does not contain any certificate"
	if _, err := timestampToken.SigningCertificate(&timestampToken.SignerInfos[0]); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampTokenWithSigningCertificateV1.p7s")
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "failed to get SigningCertificateV2 from signed attributes: attribute not found"
	if _, err := timestampToken.SigningCertificate(&timestampToken.SignerInfos[0]); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestTimestamp(t *testing.T) {
	timestampToken, err := getTimestampTokenFromPath("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal(err)
	}
	tstInfo, err := timestampToken.Info()
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg := "invalid TSTInfo: mismatched message"
	if _, err := tstInfo.Validate([]byte("invalid")); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal(err)
	}
	tstInfo, err = timestampToken.Info()
	if err != nil {
		t.Fatal(err)
	}
	timestampLimit, err := tstInfo.Validate([]byte("notation"))
	if err != nil {
		t.Fatalf("expected nil error, but got %v", err)
	}
	expectedLowerLimit := time.Date(2021, time.September, 17, 14, 9, 9, 0, time.UTC)
	expectedUpperLimit := time.Date(2021, time.September, 17, 14, 9, 11, 0, time.UTC)
	if timestampLimit.LowerLimit != expectedLowerLimit {
		t.Fatalf("expected timestamp %s, but got %s", expectedLowerLimit, timestampLimit.LowerLimit)
	}
	if timestampLimit.UpperLimit != expectedUpperLimit {
		t.Fatalf("expected timestamp %s, but got %s", expectedUpperLimit, timestampLimit.UpperLimit)
	}
}

func TestValidateInfo(t *testing.T) {
	message := []byte("notation")
	var tstInfoErr *TSTInfoError

	var tstInfo *TSTInfo
	expectedErrMsg := "invalid TSTInfo: timestamp token info cannot be nil"
	err := tstInfo.validate(message)
	if err == nil || !errors.As(err, &tstInfoErr) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err := getTimestampTokenFromPath("testdata/TimeStampTokenWithTSTInfoVersion2.p7s")
	if err != nil {
		t.Fatal(err)
	}
	tstInfo, err = timestampToken.Info()
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "invalid TSTInfo: timestamp token info version must be 1, but got 2"
	err = tstInfo.validate(message)
	if err == nil || !errors.As(err, &tstInfoErr) || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/SHA1TimeStampToken.p7s")
	if err != nil {
		t.Fatal(err)
	}
	tstInfo, err = timestampToken.Info()
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "invalid TSTInfo: unrecognized hash algorithm: 1.2.840.113549.1.1.5"
	if err := tstInfo.validate(message); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal(err)
	}
	tstInfo, err = timestampToken.Info()
	if err != nil {
		t.Fatal(err)
	}
	expectedErrMsg = "invalid TSTInfo: mismatched message"
	if err := tstInfo.validate([]byte("invalid")); err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	timestampToken, err = getTimestampTokenFromPath("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal(err)
	}
	tstInfo, err = timestampToken.Info()
	if err != nil {
		t.Fatal(err)
	}
	if err := tstInfo.validate(message); err != nil {
		t.Fatalf("expected nil error, but got %v", err)
	}
}

func getTimestampTokenFromPath(path string) (*SignedToken, error) {
	timestampToken, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseSignedToken(timestampToken)
}
