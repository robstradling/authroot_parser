package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/TomOnTime/utfutil"
	"go.mozilla.org/pkcs7"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

type Sequence struct {
	Data			asn1.RawValue
}

type CTLEntryValue struct {
	Data			[]byte
}

type CTLEntryAttribute struct {
	Type			asn1.ObjectIdentifier
	Value			CTLEntryValue `asn1:"set"`
}

type CTLEntry struct {
	CertFingerprint	[]byte
	Attributes		[]CTLEntryAttribute `asn1:"set"`
}

type CTL struct {
	Signers			[]asn1.ObjectIdentifier
	SequenceNumber	*big.Int
	EffectiveDate	time.Time
	DigestAlgorithm	pkix.AlgorithmIdentifier
	Entries			[]CTLEntry
}

func oidList(data []byte) string {
	var oids []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(data, &oids); err != nil {
		panic(err)
	}
	var s string
	for _, oid := range oids {
		s += fmt.Sprintf(" %s", oid.String())
	}
	return s
}

type PolicyQualifier struct {
	OID				asn1.ObjectIdentifier
	Bits			asn1.BitString
}

type CertPolicy struct {
	OID				asn1.ObjectIdentifier
	Qualifier		[]PolicyQualifier
}

type CertPolicies struct {
	Policies		[]CertPolicy
}

func policyList(data []byte) string {
	// Wrap policy list in a SEQUENCE.
	seq := Sequence{Data: asn1.RawValue{FullBytes: data}}
	var der_pol []byte
	var err error
	if der_pol, err = asn1.Marshal(seq); err != nil {
		panic(err)
	}

	var policies CertPolicies
	if _, err = asn1.Unmarshal(der_pol, &policies); err != nil {
		panic(err)
	}

	var s string
	for _, pol := range policies.Policies {
		if pol.OID.String() == "1.3.6.1.4.1.311.94.1.1" {
			s += " EV Disabled"
		} else {
			s += " " + pol.OID.String()
		}
	}
	return s
}

func msFiletime(data []byte) string {
	switch len(data) {
		case 8: return fmt.Sprintf("%v", time.Date(1601, time.January, 1, 0, 0, int(binary.LittleEndian.Uint64(data) / 10000000), 0, time.UTC))
		case 0: return fmt.Sprintf("Since forever")
		default: panic(fmt.Errorf("Unexpected length (%d)", len(data)))
	}
}

func utf16to8(data []byte) string {
	if bytes, err := ioutil.ReadAll(utfutil.BytesReader(data, utfutil.WINDOWS)); err != nil {
		panic(err)
	} else {
		return string(bytes[0:len(bytes)-1])
	}
}

func main() {
	// Read DER-encoded authroot PKCS#7 file.
	var err error
	var authroot_data []byte
	if authroot_data, err = ioutil.ReadFile(os.Args[1]); err != nil {
		panic(err)
	}

	// Parse the PKCS#7, whose Content is assumed to have type szOID_CTL (1.3.6.1.4.1.311.10.1).
	var p7 *pkcs7.PKCS7
	if p7, err = pkcs7.Parse(authroot_data); err != nil {
		panic(err)
	}

	// Wrap p7.Content in a SEQUENCE.
	seq := Sequence{Data: asn1.RawValue{FullBytes: p7.Content}}
	var der_ctl []byte
	if der_ctl, err = asn1.Marshal(seq); err != nil {
		panic(err)
	}

	// Parse the CTL.
	var ctl CTL
	if _, err = asn1.Unmarshal(der_ctl, &ctl); err != nil {
		panic(err)
	}
	fmt.Printf("CTL Type: %s\n", ctl.Signers[0].String())
	fmt.Printf("Sequence Number: %v\n", ctl.SequenceNumber)
	fmt.Printf("Effective Date: %v\n", ctl.EffectiveDate)
	fmt.Printf("Digest Algorithm: %s\n", ctl.DigestAlgorithm.Algorithm.String())
	fmt.Printf("Number of Entries: %d\n", len(ctl.Entries))

	for _, entry := range ctl.Entries {
		fmt.Printf("\nCert Fingerprint: %s\n", hex.EncodeToString(entry.CertFingerprint))
		for _, attribute := range entry.Attributes {
			fmt.Printf("  ")
			fmt.Printf("[%s] ", attribute.Type.String())
			switch attribute.Type.String() {
				case "1.3.6.1.4.1.311.10.11.9": fmt.Printf("CERT_ENHKEY_USAGE_PROP_ID:%s", oidList(attribute.Value.Data))
				case "1.3.6.1.4.1.311.10.11.11": fmt.Printf("CERT_FRIENDLY_NAME_PROP_ID: %s", utf16to8(attribute.Value.Data))
				case "1.3.6.1.4.1.311.10.11.20": fmt.Printf("CERT_KEY_IDENTIFIER_PROP_ID: %s", hex.EncodeToString(attribute.Value.Data))
				case "1.3.6.1.4.1.311.10.11.29": fmt.Printf("CERT_SUBJECT_NAME_MD5_HASH_PROP_ID: %s", hex.EncodeToString(attribute.Value.Data))
				case "1.3.6.1.4.1.311.10.11.83": fmt.Printf("CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID:%s", policyList(attribute.Value.Data))
				case "1.3.6.1.4.1.311.10.11.98": fmt.Printf("CERT_AUTH_ROOT_SHA256_HASH_PROP_ID: %s", hex.EncodeToString(attribute.Value.Data))
				case "1.3.6.1.4.1.311.10.11.104": fmt.Printf("CERT_DISALLOWED_FILETIME_PROP_ID: %s", msFiletime(attribute.Value.Data))
				case "1.3.6.1.4.1.311.10.11.105": fmt.Printf("CERT_ROOT_PROGRAM_CHAIN_POLICIES_PROP_ID:%s", oidList(attribute.Value.Data))
				case "1.3.6.1.4.1.311.10.11.122": fmt.Printf("DISALLOWED_ENHKEY_USAGE:%s", oidList(attribute.Value.Data))
				case "1.3.6.1.4.1.311.10.11.126": fmt.Printf("NotBefore?: %s", msFiletime(attribute.Value.Data))
				case "1.3.6.1.4.1.311.10.11.127": fmt.Printf("NotBefore'd OIDs?:%s", oidList(attribute.Value.Data))
				default: panic(fmt.Errorf("%s: UNEXPECTED!", attribute.Type.String()))
			}
			fmt.Printf("\n")
		}
	}
}
