package rfc3161

import (
	"encoding/asn1"
	"errors"
	"strings"
)

// PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
type PKIFreeText []asn1.RawValue

// Append returns a new copy of the PKIFreeText with the provided string
// appended.
func (ft PKIFreeText) Append(t string) PKIFreeText {
	return append(ft, asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagUTF8String,
		Bytes: []byte(t),
	})
}

// Strings decodes the PKIFreeText into a []string.
func (ft PKIFreeText) Strings() ([]string, error) {
	strs := make([]string, len(ft))

	for i := range ft {
		if rest, err := asn1.Unmarshal(ft[i].FullBytes, &strs[i]); err != nil {
			return nil, err

		} else if len(rest) != 0 {
			return nil, errors.New("trailing data after PKIFreeText")
		}
	}

	return strs, nil
}

// PKIStatusInfo contains complete information about the status of the Time Stamp Response
type PKIStatusInfo struct {
	Status       PKIStatus
	StatusString PKIFreeText    `asn1:"optional"`
	FailInfo     PKIFailureInfo `asn1:"optional"`
}

func (si *PKIStatusInfo) Error() string {
	var output string
	output += si.Status.Error()
	if si.Status.IsError() {
		output += ": " + si.FailInfo.Error()
	}

	statusString := ""
	if ft, err := si.StatusString.Strings(); err == nil && len(ft) > 0 {
		statusString = strings.Join(ft, " :: ")
	}

	if statusString != "" {
		output += ": " + statusString
	}

	return output
}

// PKIStatus carries the specific status code about the status of the Time Stamp Response.
type PKIStatus int

// When the status contains the value zero or one, a TimeStampToken MUST
// be present.  When status contains a value other than zero or one, a
// TimeStampToken MUST NOT be present.  One of the following values MUST
//  be contained in status
const (
	StatusGranted                = iota // When the PKIStatus contains the value zero a TimeStampToken, as requested, is present.
	StatusGrantedWithMods               // When the PKIStatus contains the value one a TimeStampToken, with modifications, is present.
	StatusRejection                     // When the request is invalid or otherwise rejected.
	StatusWaiting                       // When the request is being processed and the client should check back later.
	StatusRevocationWarning             // Warning that a revocation is imminent.
	StatusRevocationNotification        // Notification that a revocation has occurred.
)

// IsError checks if the given Status is an error
func (status PKIStatus) IsError() bool {
	return (status != StatusGranted && status != StatusGrantedWithMods && status != StatusWaiting)
}

func (status PKIStatus) Error() string {
	switch status {
	case StatusGranted:
		return "A TimeStampToken, as requested, is present"
	case StatusGrantedWithMods:
		return "A TimeStampToken, with modifications, is present"
	case StatusRejection:
		return "The request is invalid or otherwise rejected"
	case StatusWaiting:
		return "The request is being processed and the client should check back later"
	case StatusRevocationWarning:
		return "A revocation is imminent"
	case StatusRevocationNotification:
		return "A revocation has occurred"
	default:
		return "Invalid PKIStatus"
	}
}

// PKIFailureInfo as defined by RFC 3161 2.4.2
type PKIFailureInfo int

// When the TimeStampToken is not present, the failInfo indicates the reason why the time-stamp
// request was rejected and may be one of the following values.
const (
	FailureBadAlg               = 0  // Unrecognized or unsupported Algorithm Identifier.
	FailureBadRequest           = 2  // Transaction not permitted or supported.
	FailureDataFormat           = 5  // The data submitted has the wrong format.
	FailureTimeNotAvailabe      = 14 // The TSA's time source is not available.
	FailureUnacceptedPolicy     = 15 // The requested TSA policy is not supported by the TSA.
	FailureUunacceptedExtension = 16 // The requested extension is not supported by the TSA.
	FailureAddInfoNotAvailable  = 17 // The additional information requested could not be understood or is not available.
	FailureSystemFailure        = 25 // The request cannot be handled due to system failure.
)

func (fi PKIFailureInfo) Error() string {
	switch fi {
	case FailureBadAlg:
		return "Unrecognized or unsupported Algorithm Identifier"
	case FailureBadRequest:
		return "Transaction not permitted or supported"
	case FailureDataFormat:
		return "The data submitted has the wrong format"
	case FailureTimeNotAvailabe:
		return "The TSA's time source is not available"
	case FailureUnacceptedPolicy:
		return "The requested TSA policy is not supported by the TSA"
	case FailureUunacceptedExtension:
		return "The requested extension is not supported by the TSA"
	case FailureAddInfoNotAvailable:
		return "The additional information requested could not be understood or is not available"
	case FailureSystemFailure:
		return "The request cannot be handled due to system failure"
	default:
		return "Invalid PKIFailureInfo"
	}
}
