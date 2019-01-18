package encoder

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ed25519"
)

// ecPrivateKey is an ASN.1 encoded EC key defined here:
// https://tools.ietf.org/html/rfc5915
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// pkcs8PrivateKey is an ASN.1 encoded EC key defined here:
// https://tools.ietf.org/html/rfc5208
type pkcs8PrivateKey struct {
	Version             int
	PrivateKeyAlgorithm pkix.AlgorithmIdentifier
	PrivateKey          []byte
}

// publicKey is an ASN.1 encoded Subject Public Key Info, defined here:
// https://tools.ietf.org/html/rfc5280#section-4.1.2.7
type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// ParseAsn1EcKey parses DER encoded bytes using the ASN.1 EC
// structure, returning public/secret key material.  The object
// identifier must be manually set when EC object is PKCS8 encoded
// Compare to: x509.ParseECPrivateKey()
func ParseAsn1EcKey(der []byte, setOid *asn1.ObjectIdentifier) (*CryptoKey, error) {
	var ec ecPrivateKey
	_, err := asn1.Unmarshal(der, &ec)
	if err != nil {
		return nil, errors.New("asn1: failed to parse EC private key" + err.Error())
	}
	if ec.Version != 1 {
		return nil, fmt.Errorf("asn1: unknown EC private key version %d", ec.Version)
	}

	ck := CryptoKey{}
	// Manually se tthe OID
	if setOid != nil {
		ck.Algorithm = setOid
	} else {
		ck.Algorithm = &ec.NamedCurveOID
	}

	if ck.Algorithm.Equal(oidPrivateKeyP256) {
		ck.Secret = ec.PrivateKey
		ck.PublicKey = getCompressedPubkey(ec.PublicKey.Bytes)

	} else if ck.Algorithm.Equal(oidPrivateKeySecp256k1) {
		ck.Secret = ec.PrivateKey
		ck.PublicKey = getCompressedPubkey(ec.PublicKey.Bytes)
	} else {
		return nil, fmt.Errorf("asn1: unsupported algorithm in ec: %v", ck.Algorithm)
	}
	return &ck, nil
}

// ParseAsn1Pkcs8Key parses DER encoded bytes using the ASN.1 PKCS8
// structure and returns our public/secret keys material
// Compare to: x509.ParsePKCS8PrivateKey()
func ParseAsn1Pkcs8Key(der []byte) (*CryptoKey, error) {
	var pkcs8 pkcs8PrivateKey
	_, err := asn1.Unmarshal(der, &pkcs8)
	if err != nil {
		return nil, err
	}

	if pkcs8.PrivateKeyAlgorithm.Algorithm.Equal(oidPublicKeyECDSA) {
		// Is a generic ECDSA key, now parse the specific EC type
		bytes := pkcs8.PrivateKeyAlgorithm.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}

		// Parse embedded EC ASN.1 content
		ec, err := ParseAsn1EcKey(pkcs8.PrivateKey, namedCurveOID)
		if err != nil {
			return nil, err
		}
		return ec, nil
	} else if pkcs8.PrivateKeyAlgorithm.Algorithm.Equal(oidPrivateKeyEd25519) {
		// Per https://tools.ietf.org/html/draft-ietf-curdle-pkix-10, the private key is an OCTET STRING
		// which is encoded like: 0x04,0x20,<pk of length 0x20>
		if pkcs8.PrivateKey[0] != 0x04 || pkcs8.PrivateKey[1] != 0x20 || len(pkcs8.PrivateKey) != 0x20+2 {
			return nil, errors.New("asn1: Incorrectly formatted ed25519 seed")
		}
		// Strip the leading two identifying bytes
		ed := ed25519.NewKeyFromSeed(pkcs8.PrivateKey[2:])
		ck := CryptoKey{
			Algorithm: &oidPrivateKeyEd25519,
			Secret:    ed,
			PublicKey: ed.Public().(ed25519.PublicKey),
		}
		return &ck, nil
	}
	return nil, fmt.Errorf("asn1: unsupported algorithm in pkcs8: %v", pkcs8.PrivateKeyAlgorithm.Algorithm)
}

// ParseAsn1Pubkey parses DER encoded bytes using the ASN.1
// Public Key structure and returns our public key material
// Compare to: x509.ParsePKIXPublicKey()
func ParseAsn1Pubkey(der []byte) (*CryptoKey, error) {

	var pubKey subjectPublicKeyInfo
	// Parse the public key
	if rest, err := asn1.Unmarshal(der, &pubKey); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	// Parse the algo
	paramsData := pubKey.Algorithm.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	asn1.Unmarshal(paramsData, namedCurveOID)

	return &CryptoKey{
		Algorithm: namedCurveOID,
		PublicKey: getCompressedPubkey(pubKey.PublicKey.Bytes),
	}, nil

}

// GetCompressedPubkey for the given ECDSA Public Key, defined
// as the encoded LSB of Y followed by the X Coordinate of the key
func getCompressedPubkey(pubkey []byte) []byte {
	X := pubkey[1:33]
	var Y, YMod big.Int
	Y.SetBytes(pubkey[33:])

	var prefix []byte
	if YMod.Mod(&Y, big.NewInt(2)).Cmp(big.NewInt(1)) == 0 {
		prefix = []byte{0x03}
	} else {
		prefix = []byte{0x02}
	}
	compressed := append(prefix, X...)
	return compressed
}
