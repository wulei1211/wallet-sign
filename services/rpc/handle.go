package rpc

import (
	"context"
	"errors"
	"github.com/ethereum/go-ethereum/log"
	"github.com/wulei1211/wallet-sign/leveldb"
	"github.com/wulei1211/wallet-sign/protobuf"
	"github.com/wulei1211/wallet-sign/ssm"

	"github.com/wulei1211/wallet-sign/protobuf/wallet"
)

const BearerToken = "DappLinkTheWeb300012121"

func (s *RpcService) GetSupportSignType(ctx context.Context, in *wallet.SupportSignRequest) (*wallet.SupportSignResponse, error) {
	if in.ConsumerToken != BearerToken {
		return &wallet.SupportSignResponse{
			Code:        wallet.ReturnCode_ERROR,
			Message:     "bearer token is error",
			SignWayList: nil,
		}, nil
	}
	var signWay []*wallet.SignWay
	signWay = append(signWay, &wallet.SignWay{Name: "ecdsa"})
	signWay = append(signWay, &wallet.SignWay{Name: "eddsa"})
	return &wallet.SupportSignResponse{
		Code:        wallet.ReturnCode_SUCCESS,
		Message:     "get sign type success",
		SignWayList: signWay,
	}, nil
}

func (s *RpcService) CreateKeyPairsExportPublicKeyList(ctx context.Context, in *wallet.CreateKeyPairAndExportPublicKeyRequest) (*wallet.CreateKeyPairAndExportPublicKeyResponse, error) {
	resp := &wallet.CreateKeyPairAndExportPublicKeyResponse{
		Code: wallet.ReturnCode_ERROR,
	}

	if in.ConsumerToken != BearerToken {
		resp.Message = "bearer token is error"
		return resp, nil
	}

	cryptoType, err := protobuf.ParseTransactionType(in.SignType)
	if err != nil {
		resp.Message = "input sign type error"
		return resp, nil
	}

	if in.KeyNum > 20000 {
		resp.Message = "Number must be less than 20000"
		return resp, nil
	}

	var keyList []leveldb.Key
	var exportPublicKeyList []*wallet.ExportPublicKey

	for counter := 0; counter < int(in.KeyNum); counter++ {
		var priKeyStr, pubKeyStr, compressPubkeyStr string
		var err error

		switch cryptoType {
		case protobuf.ECDSA:
			priKeyStr, pubKeyStr, compressPubkeyStr, err = ssm.CreateECDSAKeyPair()
		case protobuf.EDDSA:
			priKeyStr, pubKeyStr, err = ssm.CreateEdDSAKeyPair()
			compressPubkeyStr = pubKeyStr
		default:
			return nil, errors.New("unsupported key type")
		}
		if err != nil {
			log.Error("create key pair fail", "err", err)
			return nil, err
		}

		keyItem := leveldb.Key{
			PrivateKey: priKeyStr,
			Pubkey:     pubKeyStr,
		}
		pukItem := &wallet.ExportPublicKey{
			CompressPublicKey: compressPubkeyStr,
			PublicKey:         pubKeyStr,
		}
		exportPublicKeyList = append(exportPublicKeyList, pukItem)
		keyList = append(keyList, keyItem)
	}

	isOk := s.db.StoreKeys(keyList)
	if !isOk {
		log.Error("store keys fail", "isOk", isOk)
		return nil, errors.New("store keys fail")
	}
	resp.Code = wallet.ReturnCode_SUCCESS
	resp.Message = "create keys success"
	resp.PublicKeyList = exportPublicKeyList
	return resp, nil
}

func (s *RpcService) SignMessageSignature(ctx context.Context, in *wallet.SignMessageSignatureRequest) (*wallet.SignMessageSignatureResponse, error) {
	resp := &wallet.SignMessageSignatureResponse{
		Code: wallet.ReturnCode_ERROR,
	}
	cryptoType, err := protobuf.ParseTransactionType(in.SignType)
	if err != nil {
		resp.Message = "input type error"
		return resp, nil
	}

	privKey, isOk := s.db.GetPrivKey(in.PublicKey)
	if !isOk {
		return nil, errors.New("get private key by public key fail")
	}

	var signature string
	var err2 error

	switch cryptoType {
	case protobuf.ECDSA:
		signature, err2 = ssm.SignECDSAMessage(privKey, in.TxMessageHash)
	case protobuf.EDDSA:
		signature, err2 = ssm.SignEdDSAMessage(privKey, in.TxMessageHash)
	default:
		return nil, errors.New("unsupported key type")
	}
	if err2 != nil {
		return nil, err2
	}
	resp.Message = "sign tx message success"
	resp.Signature = signature
	resp.Code = wallet.ReturnCode_SUCCESS
	return resp, nil
}

func (s *RpcService) SignBatchMessageSignature(ctx context.Context, in *wallet.SignBatchMessageSignatureRequest) (*wallet.SignBatchMessageSignatureResponse, error) {
	resp := &wallet.SignBatchMessageSignatureResponse{
		Code: wallet.ReturnCode_SUCCESS,
	}
	var msgSignatureList []*wallet.MessageSignature
	for _, msgHash := range in.MessageHashes {
		cryptoType, err := protobuf.ParseTransactionType(msgHash.SignType)
		if err != nil {
			log.Error("parse transaction error", "messageHash", msgHash.TxMessageHash)
		}
		privKey, isOk := s.db.GetPrivKey(msgHash.PublicKey)
		if !isOk {
			log.Error("get private key by public key fail", "err", err)
		}
		var signature string
		var err2 error
		switch cryptoType {
		case protobuf.ECDSA:
			signature, err2 = ssm.SignECDSAMessage(privKey, msgHash.TxMessageHash)
		case protobuf.EDDSA:
			signature, err2 = ssm.SignEdDSAMessage(privKey, msgHash.TxMessageHash)
		default:
			return nil, errors.New("unsupported key type")
		}
		if err2 != nil {
			log.Error("sign message hash fail", "err", err)
			continue
		}
		sigItem := &wallet.MessageSignature{
			TxMessageHash: msgHash.TxMessageHash,
			Signature:     signature,
		}
		msgSignatureList = append(msgSignatureList, sigItem)
	}
	resp.Message = "sign batch tx message success"
	resp.MessageSignatures = msgSignatureList
	resp.Code = wallet.ReturnCode_SUCCESS
	return resp, nil
}
