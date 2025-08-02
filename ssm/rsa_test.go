package ssm

import (
	"testing"
)

func TestRSA_CreateKeyPair(t *testing.T) {
	rsa := &RSA{}
	privateKey, publicKey, publicKeyHex, err := rsa.CreateKeyPair()

	if err != nil {
		t.Fatalf("CreateKeyPair failed: %v", err)
	}

	if privateKey == "" || privateKey == EmptyHexString {
		t.Error("Private key should not be empty")
	}

	if publicKey == "" || publicKey == EmptyHexString {
		t.Error("Public key should not be empty")
	}

	if publicKeyHex == "" || publicKeyHex == EmptyHexString {
		t.Error("Public key hex should not be empty")
	}

	t.Logf("Private Key: %s", privateKey)
	t.Logf("Public Key: %s", publicKey)
	t.Logf("Public Key Hex: %s", publicKeyHex)

}

func TestRSA_SignAndVerify(t *testing.T) {
	rsa := &RSA{}

	// 创建密钥对
	privateKey, _, publicKeyHex, err := rsa.CreateKeyPair()
	if err != nil {
		t.Fatalf("CreateKeyPair failed: %v", err)
	}

	// 测试消息
	testMessage := "Hello, RSA signing test!"
	messageHex := "48656c6c6f2c20525341207369676e696e67207465737421" // "Hello, RSA signing test!" 的十六进制

	// 签名
	signature, err := rsa.SignMessage(privateKey, messageHex)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	if signature == "" {
		t.Error("Signature should not be empty")
	}

	// 验证签名
	valid, err := rsa.VerifySignature(publicKeyHex, messageHex, signature)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}

	if !valid {
		t.Error("Signature verification should succeed")
	}

	t.Logf("Test message: %s", testMessage)
	t.Logf("Message hex: %s", messageHex)
	t.Logf("Signature: %s", signature[:50]+"...")
	t.Logf("Verification result: %v", valid)
}

func TestRSA_VerifyInvalidSignature(t *testing.T) {
	rsa := &RSA{}

	// 创建密钥对
	privateKey, _, publicKeyHex, err := rsa.CreateKeyPair()
	if err != nil {
		t.Fatalf("CreateKeyPair failed: %v", err)
	}

	// 测试消息
	messageHex := "48656c6c6f2c20525341207369676e696e67207465737421"

	// 签名
	signature, err := rsa.SignMessage(privateKey, messageHex)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	// 使用错误的公钥验证（使用不同的密钥对）
	_, _, wrongPublicKeyHex, err := rsa.CreateKeyPair()
	if err != nil {
		t.Fatalf("CreateKeyPair failed: %v", err)
	}

	// 使用错误的公钥验证
	valid, err := rsa.VerifySignature(wrongPublicKeyHex, messageHex, signature)
	if err == nil {
		t.Error("VerifySignature with wrong public key should return error")
	}

	if valid {
		t.Error("Signature verification with wrong public key should fail")
	}

	// 使用正确的公钥验证
	valid, err = rsa.VerifySignature(publicKeyHex, messageHex, signature)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}

	if !valid {
		t.Error("Signature verification with correct public key should succeed")
	}

	t.Logf("Verification with wrong key: %v", valid)
	t.Logf("Verification with correct key: %v", valid)
}

func TestRSA_ImplementsEncryptionInterface(t *testing.T) {
	// 验证 RSA 实现了 Encryption 接口
	var _ Encryption = &RSA{}

	// 验证 RSA 在全局映射中正确注册
	rsaImpl, exists := EncryptionMap[RSA_STR]
	if !exists {
		t.Fatal("RSA implementation not found in EncryptionMap")
	}

	// 验证返回的实现是 RSA 类型
	if _, ok := rsaImpl.(*RSA); !ok {
		t.Fatal("EncryptionMap contains wrong type for RSA")
	}

	t.Log("RSA correctly implements Encryption interface and is registered")
}
