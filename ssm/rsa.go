package ssm

type RSA struct {
}

func (R RSA) CreateKeyPair() (string, string, string, error) {
	//TODO implement me
	return "", "", "", nil
}

func (R RSA) SignMessage(privKey string, txMsg string) (string, error) {
	//TODO implement me
	return "", nil
}

func (R RSA) VerifySignature(publicKey, txHash, signature string) (bool, error) {
	//TODO implement me
	return false, nil
}
