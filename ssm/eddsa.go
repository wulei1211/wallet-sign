package ssm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"

	"github.com/ethereum/go-ethereum/log"
)

type EDDSA struct {
}

func (eddsa *EDDSA) CreateKeyPair() (string, string, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Error("create key pair fail:", "err", err)
		return EmptyHexString, EmptyHexString, EmptyHexString, nil
	}
	return hex.EncodeToString(privateKey), hex.EncodeToString(publicKey), hex.EncodeToString(publicKey), nil
}

func (eddsa *EDDSA) SignMessage(privKey string, txMsg string) (string, error) {
	privateKey, err := hex.DecodeString(privKey)
	if err != nil {
		log.Error("Decode private key string fail", "err", err)
		return "", err
	}
	txMsgByte, err := hex.DecodeString(txMsg)
	if err != nil {
		log.Error("Decode tx message fail", "err", err)
		return "", err
	}
	signMsg := ed25519.Sign(privateKey, txMsgByte)

	return hex.EncodeToString(signMsg), nil
}

func (eddsa *EDDSA) VerifySignature(publicKey, txHash, sig string) (bool, error) {
	publicKeyByte, _ := hex.DecodeString(publicKey)
	msgHashByte, _ := hex.DecodeString(txHash)
	signature, _ := hex.DecodeString(sig)
	return ed25519.Verify(publicKeyByte, msgHashByte, signature), nil
}
