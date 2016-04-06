package rfc3161

import (
	"encoding/asn1"
	"github.com/cryptoballot/entropychecker"
	"mime"
)

// OID Identifiers
var (
	// RFC-2630: iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2
	OidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// RFC-3161: iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 4
	OidContentTypeTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

// Supported Extensions.
var supportedExtensions []asn1.ObjectIdentifier

// RegisterExtension registers a supported Extension.
// This is intended to be called from the init function in
// packages that implement support for these extensions.
// A TimeStampReq or TimeStampResp with an unregistered
// critical extension will return an error when verified.
func RegisterExtension(extension asn1.ObjectIdentifier) {
	if supportedExtensions == nil {
		supportedExtensions = make([]asn1.ObjectIdentifier, 0, 0)
	}

	// Check if it already exists
	for _, ext := range supportedExtensions {
		if ext.Equal(extension) {
			return
		}
	}

	// Add it
	supportedExtensions = append(supportedExtensions, extension)
}

// List all supported extensions
func ListExtensions() []asn1.ObjectIdentifier {
	if supportedExtensions == nil {
		return make([]asn1.ObjectIdentifier, 0, 0)
	} else {
		return supportedExtensions
	}
}

func setMimeTypes() error {
	err := mime.AddExtensionType(".tsq", "application/timestamp-query")
	if err != nil {
		return err
	}

	err = mime.AddExtensionType(".tsr", "application/timestamp-reply")
	if err != nil {
		return err
	}

	return nil
}

func init() {
	// Make sure we have sufficient entropy and fail to start if there isn't
	// This only works on Linux.
	err := entropychecker.WaitForEntropy()
	if err != nil && err != entropychecker.ErrUnsupportedOS {
		panic(err)
	}

	err = setMimeTypes()
	if err != nil {
		panic(err)
	}
}