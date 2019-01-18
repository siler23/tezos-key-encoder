package encoder

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

// CryptoKey stores the fields needed to derive cryptocurrency
// specific sk, pk and pkh from a public key algorithm
type CryptoKey struct {
	Secret    []byte
	PublicKey []byte
	Algorithm *asn1.ObjectIdentifier
}

// ParsePEM and return the DER encoded ASN.1 bytes along with
// the ASN.1 type or error
func ParsePEM(pemBytes []byte) (*CryptoKey, error) {
	var ck *CryptoKey
	var err error

	for rest := pemBytes; ; {
		block, more := pem.Decode(rest)
		rest = more

		if block.Type == pemEcMarker {
			ck, err = ParseAsn1EcKey(block.Bytes, nil)
			if err != nil {
				return nil, err
			}
		} else if block.Type == pemPkcs8Marker {
			ck, err = ParseAsn1Pkcs8Key(block.Bytes)
			if err != nil {
				return nil, err
			}
		} else if block.Type == pemEcParametersMarker {
			// PEM Parameters re-encode the curve's parameters which are known
			// for the standard curves we're expecting and can be safely skipped
			continue
		} else if block.Type == pemPubkeyMarker {
			ck, err = ParseAsn1Pubkey(block.Bytes)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("pem: unknown block type found in PEM File: %v", block.Type)
		}

		// Terminate when a single block has been parsed
		if ck != nil {
			if len(rest) != 0 {
				return nil, fmt.Errorf("pem: key parsed but content remained in PEM file")
			}
			return ck, nil
		}
	}
}

const (
	// PEM Markers
	pemPkcs8Marker        = "PRIVATE KEY"
	pemEcMarker           = "EC PRIVATE KEY"
	pemEcParametersMarker = "EC PARAMETERS"
	pemPubkeyMarker       = "PUBLIC KEY"
)
