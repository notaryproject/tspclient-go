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

// Package pki contains Status of a timestamping response defined in RFC 3161.
package pki

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrUnknownStatus is used when PKIStatus is not supported
var ErrUnknownStatus = errors.New("unknown PKIStatus")

// ErrUnknownFailureInfo is used when PKIFailureInfo is not supported or does
// not exists
var ErrUnknownFailureInfo = errors.New("unknown PKIFailureInfo")

// Status is PKIStatus defined in RFC 3161 2.4.2.
type Status int

const (
	StatusGranted                Status = 0 // you got exactly what you asked for
	StatusGrantedWithMods        Status = 1 // you got something like what you asked for
	StatusRejection              Status = 2 // you don't get it, more information elsewhere in the message
	StatusWaiting                Status = 3 // the request body part has not yet been processed, expect to hear more later
	StatusRevocationWarning      Status = 4 // this message contains a warning that a revocation is imminent
	StatusRevocationNotification Status = 5 // notification that a revocation has occurred
)

// String converts Status to string
func (s Status) String() string {
	switch s {
	case StatusGranted:
		return "granted"
	case StatusGrantedWithMods:
		return "granted with modifications"
	case StatusRejection:
		return "rejected"
	case StatusWaiting:
		return "the request body part has not yet been processed, expect to hear more later"
	case StatusRevocationWarning:
		return "warning: a revocation is imminent"
	case StatusRevocationNotification:
		return "a revocation has occurred"
	default:
		return "unknown PKIStatus " + strconv.Itoa(int(s))
	}
}

// FailureInfo is PKIFailureInfo defined in RFC 3161 2.4.2.
type FailureInfo int

const (
	FailureInfoBadAlg              FailureInfo = 0  // unrecognized or unsupported Algorithm Identifier
	FailureInfoBadRequest          FailureInfo = 2  // transaction not permitted or supported
	FailureInfoBadDataFormat       FailureInfo = 5  // the data submitted has the wrong format
	FailureInfoTimeNotAvailable    FailureInfo = 14 // the TSA's time source is not available
	FailureInfoUnacceptedPolicy    FailureInfo = 15 // the requested TSA policy is not supported by the TSA.
	FailureInfoUnacceptedExtension FailureInfo = 16 // the requested extension is not supported by the TSA.
	FailureInfoAddInfoNotAvailable FailureInfo = 17 // the additional information requested could not be understood or is not available
	FailureInfoSystemFailure       FailureInfo = 25 // the request cannot be handled due to system failure
)

// failureInfos is an array of supported PKIFailureInfo
var failureInfos = []FailureInfo{
	FailureInfoBadAlg,
	FailureInfoBadRequest,
	FailureInfoBadDataFormat,
	FailureInfoTimeNotAvailable,
	FailureInfoUnacceptedPolicy,
	FailureInfoUnacceptedExtension,
	FailureInfoAddInfoNotAvailable,
	FailureInfoSystemFailure,
}

// Error converts a FailureInfo to an error
func (fi FailureInfo) Error() error {
	switch fi {
	case FailureInfoBadAlg:
		return errors.New("unrecognized or unsupported Algorithm Identifier")
	case FailureInfoBadRequest:
		return errors.New("transaction not permitted or supported")
	case FailureInfoBadDataFormat:
		return errors.New("the data submitted has the wrong format")
	case FailureInfoTimeNotAvailable:
		return errors.New("the TSA's time source is not available")
	case FailureInfoUnacceptedPolicy:
		return errors.New("the requested TSA policy is not supported by the TSA")
	case FailureInfoUnacceptedExtension:
		return errors.New("the requested extension is not supported by the TSA")
	case FailureInfoAddInfoNotAvailable:
		return errors.New("the additional information requested could not be understood or is not available")
	case FailureInfoSystemFailure:
		return errors.New("the request cannot be handled due to system failure")
	default:
		return errors.New("unknown PKIFailureInfo " + strconv.Itoa(int(fi)))
	}
}

// FailureInfoError is a joined error of FailureInfo
type FailureInfoError struct {
	Errs []error
}

// Error prints out a concatenated error of e.Errs split by '; '
func (e *FailureInfoError) Error() string {
	var errs []string
	for _, err := range e.Errs {
		errs = append(errs, err.Error())
	}
	return strings.Join(errs, "; ")
}

// StatusInfo contains status codes and failure information for PKI messages.
//
//	PKIStatusInfo ::= SEQUENCE {
//	 status          PKIStatus,
//	 statusString    PKIFreeText     OPTIONAL,
//	 failInfo        PKIFailureInfo  OPTIONAL }
//
// PKIStatus        ::= INTEGER
// PKIFreeText      ::= SEQUENCE SIZE (1..MAX) OF UTF8String
// PKIFailureInfo   ::= BIT STRING
//
// Reference: RFC 3161 2.4.2
type StatusInfo struct {
	Status       Status
	StatusString []string       `asn1:"optional,utf8"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// Err return nil when si Status is StatusGranted or StatusGrantedWithMods
//
// Otherwise, Err returns an error with FailInfo if any.
func (si StatusInfo) Err() error {
	if si.Status != StatusGranted && si.Status != StatusGrantedWithMods {
		var errs []error
		for _, fi := range failureInfos {
			if si.FailInfo.At(int(fi)) != 0 {
				errs = append(errs, fi.Error())
			}
		}
		if len(errs) != 0 { // there is FailInfo
			return fmt.Errorf("invalid response with status code %d: %s. Failure info: %w", si.Status, si.Status.String(), &FailureInfoError{Errs: errs})
		}
		return fmt.Errorf("invalid response with status code %d: %s", si.Status, si.Status.String())
	}
	return nil
}
