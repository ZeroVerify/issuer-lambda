package domain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
)

func ComputePseudonymousSubjectID(issuerID, oidcSub string, hmacKey []byte) string {
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(issuerID))
	mac.Write([]byte(":"))
	mac.Write([]byte(oidcSub))
	return hex.EncodeToString(mac.Sum(nil))
}

func SubjectPseudonymFieldElement(hexSubjectID string) (*big.Int, error) {
	b, err := hex.DecodeString(hexSubjectID)
	if err != nil {
		return nil, fmt.Errorf("decoding subject pseudonym: %w", err)
	}
	n := new(big.Int).SetBytes(b)
	n.Mod(n, babyjub.SubOrder)
	return n, nil
}
