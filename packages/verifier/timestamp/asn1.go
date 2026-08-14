// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

package timestamp

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// Object identifiers used by RFC 3161 and by the CMS layer carrying the token.
var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCTTSTInfo  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

	// oidETSIQualifiedTimestamp is the ETSI EN 319 422 statement asserting that
	// the token is a qualified electronic time stamp. Its presence is recorded
	// for information; the verifier never treats it as proof of qualification,
	// which can only be established against the EU trusted list.
	oidETSIQualifiedTimestamp = asn1.ObjectIdentifier{0, 4, 0, 19422, 1, 1}
)

// contentInfo is the CMS envelope, RFC 5652 section 3.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// encapContentInfo is the encapsulated content of a SignedData, RFC 5652
// section 5.2. For a timestamp token its type must be id-ct-TSTInfo.
type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// signedData is the CMS SignedData structure, RFC 5652 section 5.1. Only the
// fields needed to identify the encapsulated content are decoded; the remaining
// ones are kept raw because the signature itself is verified by the CMS library.
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

// pkiStatusInfo is the response status of a TimeStampResp, RFC 3161 section 2.4.2.
type pkiStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional,utf8"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// timeStampResp is the full RFC 3161 response, RFC 3161 section 2.4.2.
type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// messageImprint is the digest the timestamp covers, RFC 3161 section 2.4.1.
type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// accuracy is the declared precision of genTime, RFC 3161 section 2.4.2.
type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// tstInfo is the signed content of a timestamp token, RFC 3161 section 2.4.2.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

// PKIStatus values defined by RFC 3161 section 2.4.2.
const (
	statusGranted            = 0
	statusGrantedWithMods    = 1
	statusRejection          = 2
	statusWaiting            = 3
	statusRevocationWarning  = 4
	statusRevocationNotified = 5
)

func statusName(status int) string {
	switch status {
	case statusGranted:
		return "granted"
	case statusGrantedWithMods:
		return "granted with modifications"
	case statusRejection:
		return "rejection"
	case statusWaiting:
		return "waiting"
	case statusRevocationWarning:
		return "revocation warning"
	case statusRevocationNotified:
		return "revocation notification"
	default:
		return "unknown"
	}
}

func hashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, string) {
	switch {
	case oid.Equal(oidSHA512):
		return crypto.SHA512, "SHA-512"
	case oid.Equal(oidSHA384):
		return crypto.SHA384, "SHA-384"
	case oid.Equal(oidSHA256):
		return crypto.SHA256, "SHA-256"
	case oid.Equal(oidSHA1):
		return crypto.SHA1, "SHA-1"
	default:
		return 0, oid.String()
	}
}

func (a accuracy) duration() time.Duration {
	return time.Duration(a.Seconds)*time.Second +
		time.Duration(a.Millis)*time.Millisecond +
		time.Duration(a.Micros)*time.Microsecond
}
