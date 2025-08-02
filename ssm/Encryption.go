package ssm

type Encryption interface {
	CreateKeyPair() (string, string, string, error)
	SignMessage(privKey string, txMsg string) (string, error)
	VerifySignature(publicKey, txHash, signature string) (bool, error)
}

const (
	ECDSA_STR string = "ecdsa"
	EDDSA_STR string = "eddsa"
	RSA_STR   string = "rsa"
)

// 全局 map 来存储 Encryption 实现
var EncryptionMap = make(map[string]Encryption)

// RegisterEncryption 注册一个 Encryption 实现
func RegisterEncryption(name string, encryption Encryption) {
	EncryptionMap[name] = encryption
}

func init() {
	// 注册默认的 Encryption 实现
	RegisterEncryption(ECDSA_STR, &ECDSA{})
	RegisterEncryption(EDDSA_STR, &EDDSA{})
	RegisterEncryption(RSA_STR, &RSA{})
}
