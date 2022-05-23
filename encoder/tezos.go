package encoder

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"log"

	"golang.org/x/crypto/blake2b"

	"github.com/btcsuite/btcutil/btcd/base58"
)

// TezosKeys contains keys formatted specific to tezos reference binaries
type TezosKeys struct {
	SecretKey     string
	PublicKey     string
	PublicKeyHash string
	Curve         string
}

// GetTezosKeys extracted from these PEM Bytes
func GetTezosKeys(pemBytes []byte) *TezosKeys {

	ck, err := ParsePEM(pemBytes)
	if err != nil {
		log.Fatal(err)
	}

	tz := TezosKeys{}
	tz.SecretKey = getTzSecretKey(ck)
	tz.PublicKey = getTzPublicKey(ck)
	tz.PublicKeyHash = getTzPublicKeyHash(ck)
	tz.Curve = GetPrettyCurveName(ck.Algorithm)
	return &tz
}

// Tezos Constants from:
// https://gitlab.com/tezos/tezos/blob/master/src/lib_crypto/base58.ml
const (
	/* Public Key Hashes */
	tzEd25519PublicKeyHash   = "06a19f" // tz1
	tzSecp256k1PublicKeyhash = "06a1a1" // tz2
	tzP256PublicKeyHash      = "06a1a4" // tz3

	/* Public Keys */
	tzEd25519PublicKey   = "0d0f25d9" // edpk
	tzSecp256k1PublicKey = "03fee256" // sppk
	tzP256PublicKey      = "03b28b7f" // p2pk

	/* Secret Keys */
	tzEd25519Seed        = "0d0f3a07" // edsk (54 - seed)
	tzEd25519Secret      = "2bf64e07" // edsk (98 - secret)
	tzSecp256k1SecretKey = "11a2e0c9" //spsk
	tzP256SecretKey      = "1051eebd" // p2sk

	/* Encrypted Secret Keys */
	tzEd25519EncryptedSeed        = "075a3cb329" // edesk
	tzSecp256k1EncryptedSecretKey = "09edf1ae96" // spesk
	tzP256EncryptedSecretKey      = "09303973ab" // p2esk
)

// GetTzCurveBytes used to format keys used by default client software
func getTzPrefixBytes(algo *asn1.ObjectIdentifier) ([]byte, []byte, []byte) {
	if algo.Equal(oidPrivateKeySecp256k1) {
		pkh, _ := hex.DecodeString(tzSecp256k1PublicKeyhash)
		pk, _ := hex.DecodeString(tzSecp256k1PublicKey)
		sk, _ := hex.DecodeString(tzSecp256k1SecretKey)
		return pkh, pk, sk
	} else if algo.Equal(oidPrivateKeyP256) {
		pkh, _ := hex.DecodeString(tzP256PublicKeyHash)
		pk, _ := hex.DecodeString(tzP256PublicKey)
		sk, _ := hex.DecodeString(tzP256SecretKey)
		return pkh, pk, sk
	} else if algo.Equal(oidPrivateKeyEd25519) {
		pkh, _ := hex.DecodeString(tzEd25519PublicKeyHash)
		pk, _ := hex.DecodeString(tzEd25519PublicKey)
		sk, _ := hex.DecodeString(tzEd25519Secret)
		return pkh, pk, sk
	}
	return nil, nil, nil
}

func b58CheckEncode(prefix []byte, bytes []byte) string {
	message := append(prefix, bytes...)
	// SHA^2
	h := sha256.Sum256(message)
	h2 := sha256.Sum256(h[:])
	// Append first four of the hash
	finalMessage := append(message, h2[:4]...)
	// b58 encode the response
	encoded := base58.Encode(finalMessage)
	return encoded
}

func getTzSecretKey(ck *CryptoKey) string {
	if ck.Secret == nil {
		return ""
	}
	_, _, skPrefix := getTzPrefixBytes(ck.Algorithm)
	return b58CheckEncode(skPrefix, ck.Secret)
}

func getTzPublicKey(ck *CryptoKey) string {
	_, pkPrefix, _ := getTzPrefixBytes(ck.Algorithm)
	return b58CheckEncode(pkPrefix, ck.PublicKey)
}

func getTzPublicKeyHash(ck *CryptoKey) string {
	hash, _ := blake2b.New(20, nil)
	hash.Write(ck.PublicKey)
	bytes := hash.Sum(nil)

	pkhPrefix, _, _ := getTzPrefixBytes(ck.Algorithm)
	return b58CheckEncode(pkhPrefix, bytes[:])
}
