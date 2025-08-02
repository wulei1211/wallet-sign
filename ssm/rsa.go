package ssm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"

	"github.com/ethereum/go-ethereum/log"
)

type RSA struct {
}

func (r *RSA) CreateKeyPair() (string, string, string, error) {
	// 生成 RSA 密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Error("generate RSA key pair fail", "err", err)
		return EmptyHexString, EmptyHexString, EmptyHexString, err
	}

	// 将私钥编码为 PEM 格式
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyStr := string(pem.EncodeToMemory(privateKeyPEM))

	// 将公钥编码为 PEM 格式
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	}
	publicKeyStr := string(pem.EncodeToMemory(publicKeyPEM))

	// 将公钥转换为十六进制字符串（用于兼容性）
	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	publicKeyHex := hex.EncodeToString(publicKeyBytes)

	return privateKeyStr, publicKeyStr, publicKeyHex, nil
}

func (r *RSA) SignMessage(privKey string, txMsg string) (string, error) {
	// 解码私钥 PEM 格式
	block, _ := pem.Decode([]byte(privKey))
	if block == nil {
		log.Error("decode private key PEM fail")
		return "", nil
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Error("parse private key fail", "err", err)
		return "", err
	}

	// 解码消息
	txMsgByte, err := hex.DecodeString(txMsg)
	if err != nil {
		log.Error("decode tx message fail", "err", err)
		return "", err
	}

	// 计算消息哈希
	hash := sha256.Sum256(txMsgByte)

	// 使用私钥签名
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		log.Error("sign message fail", "err", err)
		return "", err
	}

	return hex.EncodeToString(signature), nil
}

func (r *RSA) VerifySignature(publicKey, txHash, sig string) (bool, error) {
	// 解码公钥
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		log.Error("decode public key fail", "err", err)
		return false, err
	}

	// 解析公钥
	pubKey, err := x509.ParsePKCS1PublicKey(publicKeyBytes)
	if err != nil {
		log.Error("parse public key fail", "err", err)
		return false, err
	}

	// 解码消息哈希
	txHashBytes, err := hex.DecodeString(txHash)
	if err != nil {
		log.Error("decode tx hash fail", "err", err)
		return false, err
	}

	// 解码签名
	signatureBytes, err := hex.DecodeString(sig)
	if err != nil {
		log.Error("decode signature fail", "err", err)
		return false, err
	}

	// 计算消息哈希
	hash := sha256.Sum256(txHashBytes)

	// 验证签名
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signatureBytes)
	if err != nil {
		log.Error("verify signature fail", "err", err)
		return false, err
	}

	return true, nil
}
