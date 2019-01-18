package encoder

import (
	"fmt"
	"testing"
)

type TzTest struct {
	PEM                 []byte
	TestName            string
	ExpectSecret        string
	ExpectPublicKey     string
	ExpectPublicKeyHash string
}

func test(tzTest TzTest, t *testing.T) {
	key := GetTezosKeys(tzTest.PEM)

	if key.SecretKey != tzTest.ExpectSecret {
		fmt.Println("Invalid Secret Key: ", tzTest.TestName)
		fmt.Println("Received:  ", key.SecretKey)
		fmt.Println("Expecting: ", tzTest.ExpectSecret)
		t.Fail()
	}

	if key.PublicKey != tzTest.ExpectPublicKey {
		fmt.Println("Invalid Public Key: ", tzTest.TestName)
		fmt.Println("Received:  ", key.PublicKey)
		fmt.Println("Expecting: ", tzTest.ExpectPublicKey)
		t.Fail()
	}

	if key.PublicKeyHash != tzTest.ExpectPublicKeyHash {
		fmt.Println("Invalid Public Key Hash: ", tzTest.TestName)
		fmt.Println("Received:  ", key.PublicKeyHash)
		fmt.Println("Expecting: ", tzTest.ExpectPublicKeyHash)
		t.Fail()
	}

}

func TestEd25519(t *testing.T) {
	// openssl genpkey -algorithm ed25519 -outform PEM -out ed25519.pem
	// using openssl 1.1.1+
	test(TzTest{
		PEM:                 []byte("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIO1vMi5bazdE4QwtzhZZwPWa1aqdsElOIju3KdA2CHc8\n-----END PRIVATE KEY-----"),
		TestName:            "ed25519",
		ExpectSecret:        "edskS95SXn6MnWAtAL3mSrX6TmdWRjg5uwYTT99VVsR3b3DNX8CE2SHdsGCshR4ncYyJxWCyEzFDNjXNyTtXzq3SqWcxmsFNYZ",
		ExpectPublicKey:     "edpkvVo4fLdJ5wrNC4eKLYafG78rhwwkkDAHew4y6CAPA9mno3XF93",
		ExpectPublicKeyHash: "tz1V1iyRr7gzs9uhup4cdGiWyDXc5K2yYXo9",
	}, t)
}

func TestP256(t *testing.T) {
	// openssl ecparam -genkey -name prime256v1 -outform pem -out p256.pem
	test(TzTest{
		PEM:                 []byte("-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEII8VNREdlsQo7cBAsFTa0ZKmdOcZAGfbTxLFHl+unfJEoAoGCCqGSM49\nAwEHoUQDQgAEt6NXvqKC1n9dK8oC2gTYWCdhsaJFq8quWVZEgHvt7LIckr7J4O/W\nJeX4YikPgae5ZsyPC36c9/hEztp2hJI3pg==\n-----END EC PRIVATE KEY-----"),
		TestName:            "p256 EC",
		ExpectSecret:        "p2sk3RofY8fDkk68yNNfKaEArFuiWzXmFviTgYMqacVn23aHtRDi4S",
		ExpectPublicKey:     "p2pk65y3B4XnqrY5DgNYeenyprkqfmccupy5iTSB7BFp3QPsr6DzJbb",
		ExpectPublicKeyHash: "tz3ZEKsi2LoU3K6EofhGoLE6CtzefJvzLmjb",
	}, t)
	// openssl pkcs8 -topk8 -nocrypt -in p256.pem -outform pem
	test(TzTest{
		PEM:                 []byte("-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjxU1ER2WxCjtwECw\nVNrRkqZ05xkAZ9tPEsUeX66d8kShRANCAAS3o1e+ooLWf10rygLaBNhYJ2GxokWr\nyq5ZVkSAe+3sshySvsng79Yl5fhiKQ+Bp7lmzI8Lfpz3+ETO2naEkjem\n-----END PRIVATE KEY-----"),
		TestName:            "p256 PKCS8",
		ExpectSecret:        "p2sk3RofY8fDkk68yNNfKaEArFuiWzXmFviTgYMqacVn23aHtRDi4S",
		ExpectPublicKey:     "p2pk65y3B4XnqrY5DgNYeenyprkqfmccupy5iTSB7BFp3QPsr6DzJbb",
		ExpectPublicKeyHash: "tz3ZEKsi2LoU3K6EofhGoLE6CtzefJvzLmjb",
	}, t)
	// openssl ec -in p256.pem -pubout
	test(TzTest{
		PEM:                 []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt6NXvqKC1n9dK8oC2gTYWCdhsaJF\nq8quWVZEgHvt7LIckr7J4O/WJeX4YikPgae5ZsyPC36c9/hEztp2hJI3pg==\n-----END PUBLIC KEY-----"),
		TestName:            "p256 Public",
		ExpectSecret:        "",
		ExpectPublicKey:     "p2pk65y3B4XnqrY5DgNYeenyprkqfmccupy5iTSB7BFp3QPsr6DzJbb",
		ExpectPublicKeyHash: "tz3ZEKsi2LoU3K6EofhGoLE6CtzefJvzLmjb",
	}, t)
}

func TestSecp256k1(t *testing.T) {
	// openssl ecparam -genkey -name secp256k1 -outform pem -out secp256k1.pem
	test(TzTest{
		PEM:                 []byte("-----BEGIN EC PARAMETERS-----\nBgUrgQQACg==\n-----END EC PARAMETERS-----\n-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEILuUuwBdGQ9n2E7VjBU7ftXG5A/Cyn9BQNDiwy3dUN1XoAcGBSuBBAAK\noUQDQgAEdh3WKIHTaO7eXHhJXXGLkPTGYWQm4JvWwndab6r0My7uCz9R6nVIJ5Fo\njNEpwr/VYm2nyFfCkLr4JmWeqCKefw==\n-----END EC PRIVATE KEY-----"),
		TestName:            "secp256k1 EC",
		ExpectSecret:        "spsk2rBBj5a6ahir2xZwbNkdeBuyZTxQZC9Pr6UvSAM4GNPeXfM3ix",
		ExpectPublicKey:     "sppk7c9QAGWCJEvFWp6vGBs3VuxFax7GDwWQiPXR2rGSYPN7NMQN9rP",
		ExpectPublicKeyHash: "tz2PH72CdqfsBJRsDcGfUu3UvuXwEyzqzs3s",
	}, t)
	// openssl pkcs8 -topk8 -nocrypt -in secp256k1.pem -outform pem
	test(TzTest{
		PEM:                 []byte("-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgu5S7AF0ZD2fYTtWMFTt+\n1cbkD8LKf0FA0OLDLd1Q3VehRANCAAR2HdYogdNo7t5ceEldcYuQ9MZhZCbgm9bC\nd1pvqvQzLu4LP1HqdUgnkWiM0SnCv9VibafIV8KQuvgmZZ6oIp5/\n-----END PRIVATE KEY-----"),
		TestName:            "secp256k1 PKCS8",
		ExpectSecret:        "spsk2rBBj5a6ahir2xZwbNkdeBuyZTxQZC9Pr6UvSAM4GNPeXfM3ix",
		ExpectPublicKey:     "sppk7c9QAGWCJEvFWp6vGBs3VuxFax7GDwWQiPXR2rGSYPN7NMQN9rP",
		ExpectPublicKeyHash: "tz2PH72CdqfsBJRsDcGfUu3UvuXwEyzqzs3s",
	}, t)
	// openssl ec -in secp256k1.pem -pubout
	test(TzTest{
		PEM:                 []byte("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEdh3WKIHTaO7eXHhJXXGLkPTGYWQm4JvW\nwndab6r0My7uCz9R6nVIJ5FojNEpwr/VYm2nyFfCkLr4JmWeqCKefw==\n-----END PUBLIC KEY-----"),
		TestName:            "secp256k1 Public",
		ExpectSecret:        "",
		ExpectPublicKey:     "sppk7c9QAGWCJEvFWp6vGBs3VuxFax7GDwWQiPXR2rGSYPN7NMQN9rP",
		ExpectPublicKeyHash: "tz2PH72CdqfsBJRsDcGfUu3UvuXwEyzqzs3s",
	}, t)
}
