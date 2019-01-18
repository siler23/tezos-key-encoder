Key Encoder
===========

![pipeline status](https://gitlab.com/polychain/key-encoder/badges/master/pipeline.svg) ![coverage](https://gitlab.com/polychain/key-encoder/badges/master/coverage.svg)

Encode public and secret keys from PEM => Cryptocurrency specific formats to derive usable cryptocurrency keys from an HSM or other secure environment.  Currently only supports Tezos key derivation.

**Usage:**

```shell
# Encode Keys
go run encode.go keys/secp256k1.pem
> Curve:  Secp256k1: 1.3.132.0.10
> Secret Key:  spsk2rBBj5a6ahir2xZwbNkdeBuyZTxQZC9Pr6UvSAM4GNPeXfM3ix
> Public Key:  sppk7c9QAGWCJEvFWp6vGBs3VuxFax7GDwWQiPXR2rGSYPN7NMQN9rP
> Public Key Hash:  tz2PH72CdqfsBJRsDcGfUu3UvuXwEyzqzs3s

# Test 
go test ./...
```

**Helpful OpenSSL Commands:**

```shell
# p256
openssl ecparam -genkey -name prime256v1 -outform pem      > p256.ec.pem
openssl ec -in p256.ec.pem -outform der                    > p256.ec.der
openssl pkcs8 -topk8 -nocrypt -in p256.ec.pem -outform der > p256.pkcs8.der
openssl ec -in p256.ec.pem -pubout                         > p256.pub

# secp256k1
openssl ecparam -genkey -name secp256k1 -outform pem            > secp256k1.ec.pem
openssl ec -in secp256k1.ec.pem -outform der                    > secp256k1.ec.der
openssl pkcs8 -topk8 -nocrypt -in secp256k1.ec.pem -outform der > secp256k1.pkcs8.der
openssl ec -in secp256k1.ec.pem -pubout                         > secp256k1.pub

# ed25519 (Requires OpenSSL 1.1.1+)
openssl genpkey -algorithm ed25519 -outform PEM                  > ed25519.pkcs8.pem
openssl pkcs8 -topk8 -nocrypt -in ed25519.pkcs8.pem -outform der > ed25519.pkcs8.der
```

**Future Work**

* Support encrypted keys
* Convert _from_ cryptocurrency formatted keys _to_ PEM formatted
* Better testing & validation
* Upstream Secp256k1 or ed25519 parsing to [github.com/golang/go](https://github.com/golang/go) or [supplemental crypto libraries](https://github.com/golang/crypto)
