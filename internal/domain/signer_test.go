package domain

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

var testKey = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

func decodeSig(t *testing.T, b64 string) *babyjub.Signature {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 64 {
		t.Fatalf("bad signature encoding: %v len=%d", err, len(raw))
	}
	var comp babyjub.SignatureComp
	copy(comp[:], raw)
	sig, err := comp.Decompress()
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// The student circuit checks the signature over Poseidon(pseudonym, status, issued, expires, revocation_index).
func TestSignStudentCredentialMatchesCircuitMessage(t *testing.T) {
	signer, _ := NewBabyJubJubSigner(testKey)
	pseudonym := big.NewInt(123456789)
	sigB64, err := signer.SignStudentCredential(pseudonym, "student", 1700000000, 1702592000, 7)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := poseidon.Hash([]*big.Int{pseudonym, fieldElement("student"), big.NewInt(1700000000), big.NewInt(1702592000), big.NewInt(7)})
	pub := signer.privateKey.Public()
	if !pub.VerifyPoseidon(msg, decodeSig(t, sigB64)) {
		t.Fatal("signature does not verify over the circuit's 5-field message")
	}
	other, _ := poseidon.Hash([]*big.Int{pseudonym, fieldElement("student"), big.NewInt(1700000000), big.NewInt(1702592000), big.NewInt(8)})
	if pub.VerifyPoseidon(other, decodeSig(t, sigB64)) {
		t.Fatal("signature must be bound to the revocation index")
	}
}

func TestSignRevocationIsOverCredentialIDFieldElement(t *testing.T) {
	signer, _ := NewBabyJubJubSigner(testKey)
	sigB64, _ := signer.SignRevocation("cred-1")
	pub := signer.privateKey.Public()
	if !pub.VerifyPoseidon(fieldElement("cred-1"), decodeSig(t, sigB64)) {
		t.Fatal("revocation signature must verify over fieldElement(credentialID)")
	}
}

// Writes the exact values the issuer would hand to the wallet, so the circuit tests in the evaluation repo can prove them.
// Usage: CIRCUIT_FIXTURE_OUT=/path/file.json go test ./internal/domain -run TestWriteCircuitFixture
func TestWriteCircuitFixture(t *testing.T) {
	out := os.Getenv("CIRCUIT_FIXTURE_OUT")
	if out == "" {
		t.Skip("CIRCUIT_FIXTURE_OUT not set")
	}
	signer, _ := NewBabyJubJubSigner(testKey)
	pseudonymHex := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	pseudonym, _ := SubjectPseudonymFieldElement(pseudonymHex)
	now := time.Now().Unix()
	issued, expires, idx := now-86400, now+30*86400, 7
	studentSig, _ := signer.SignStudentCredential(pseudonym, "student", issued, expires, idx)
	revSig, _ := signer.SignRevocation("11111111-2222-3333-4444-555555555555")
	b, _ := json.MarshalIndent(map[string]any{
		"pseudonymHex": pseudonymHex, "issuedAt": issued, "expiresAt": expires, "revocationIndex": idx,
		"credentialID": "11111111-2222-3333-4444-555555555555", "studentSig": studentSig, "revocationSig": revSig,
		"issuerPubKeyHex": signer.PublicKeyHex(),
	}, "", "  ")
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
