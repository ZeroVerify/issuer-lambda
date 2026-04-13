package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

type BabyJubJubSigner struct {
	privateKey babyjub.PrivateKey
}

func NewBabyJubJubSigner(rawKey []byte) (*BabyJubJubSigner, error) {
	if len(rawKey) != 32 {
		return nil, fmt.Errorf("%w: private key must be exactly 32 bytes, got %d", ErrSignatureFailed, len(rawKey))
	}
	var privKey babyjub.PrivateKey
	copy(privKey[:], rawKey)
	return &BabyJubJubSigner{privateKey: privKey}, nil
}

func (s *BabyJubJubSigner) SignField(value string) (string, error) {
	msg := fieldElement(value)
	sig := s.privateKey.SignPoseidon(msg)
	compressed := sig.Compress()
	return base64.StdEncoding.EncodeToString(compressed[:]), nil
}

func (s *BabyJubJubSigner) SignStudentCredential(
	subjectPseudonym *big.Int,
	enrollmentStatus string,
	issuedAt, expiresAt int64,
) (CircuitSignature, error) {
	msgHash, err := poseidon.Hash([]*big.Int{
		subjectPseudonym,
		fieldElement(enrollmentStatus),
		big.NewInt(issuedAt),
		big.NewInt(expiresAt),
	})
	if err != nil {
		return CircuitSignature{}, fmt.Errorf("%w: poseidon hash: %v", ErrSignatureFailed, err)
	}

	sig := s.privateKey.SignPoseidon(msgHash)

	return CircuitSignature{
		R8x: sig.R8.X.String(),
		R8y: sig.R8.Y.String(),
		S:   sig.S.String(),
	}, nil
}

func (s *BabyJubJubSigner) PublicKeyHex() string {
	pub := s.privateKey.Public()
	compressed := pub.Compress()
	return fmt.Sprintf("%x", compressed[:])
}

func fieldElement(value string) *big.Int {
	h := sha256.Sum256([]byte(value))
	n := new(big.Int).SetBytes(h[:])
	n.Mod(n, babyjub.SubOrder)
	return n
}
