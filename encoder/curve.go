package encoder

import (
	"encoding/asn1"
	"fmt"
)

var (
	// RFC 3279 Public Key Object Identifiers
	oidPrivateKeyEd25519   = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidPrivateKeyP256      = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidPublicKeyECDSA      = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPrivateKeySecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

// GetPrettyCurveName for the provided object identifier
func GetPrettyCurveName(algo *asn1.ObjectIdentifier) string {
	if algo.Equal(oidPrivateKeySecp256k1) {
		return fmt.Sprintf("Secp256k1: %v", algo.String())
	} else if algo.Equal(oidPrivateKeyP256) {
		return fmt.Sprintf("Secp256r1: %v", algo.String())
	} else if algo.Equal(oidPrivateKeyEd25519) {
		return fmt.Sprintf("ed25519: %v", algo.String())
	}
	return fmt.Sprintf("Unknown: %v", algo.String())
}
