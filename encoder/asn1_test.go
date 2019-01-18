package encoder

import (
	"encoding/hex"
	"log"
	"reflect"
	"testing"
)

func TestGetCompressedPubkey(t *testing.T) {
	input, _ := hex.DecodeString("04b7a357bea282d67f5d2bca02da04d8582761b1a245abcaae595644807bedecb21c92bec9e0efd625e5f862290f81a7b966cc8f0b7e9cf7f844ceda76849237a6")
	output, _ := hex.DecodeString("02b7a357bea282d67f5d2bca02da04d8582761b1a245abcaae595644807bedecb2")
	if !reflect.DeepEqual(getCompressedPubkey(input), output) {
		log.Println("Incorrect compressed pubkey derivation")
		t.Fail()
	}
}
