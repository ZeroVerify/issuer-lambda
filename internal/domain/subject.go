package domain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func ComputePseudonymousSubjectID(issuerID, oidcSub string, hmacKey []byte) string {
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(issuerID))
	mac.Write([]byte(":"))
	mac.Write([]byte(oidcSub))
	return hex.EncodeToString(mac.Sum(nil))
}
