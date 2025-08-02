package rpc

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/ethereum/go-ethereum/log"

	"github.com/wulei1211/wallet-sign/hsm"
	"github.com/wulei1211/wallet-sign/leveldb"
	"github.com/wulei1211/wallet-sign/protobuf/wallet"
)

const MaxReceivedMessageSize = 1024 * 1024 * 30000

type RpcServiceConfig struct {
	Hostname  string
	Port      int
	KeyPath   string
	KeyName   string
	HsmEnable bool
}

type RpcService struct {
	*RpcServiceConfig
	db        *leveldb.Keys
	HsmClient *hsm.HsmClient
	wallet.UnimplementedWalletServiceServer
	stopped atomic.Bool
}

func (s *RpcService) Stop(ctx context.Context) error {
	s.stopped.Store(true)
	return nil
}

func (s *RpcService) Stopped() bool {
	return s.stopped.Load()
}

func NewRpcService(db *leveldb.Keys, config *RpcServiceConfig) (*RpcService, error) {
	rpcService := &RpcService{
		RpcServiceConfig: config,
		db:               db,
	}
	var hsmCli *hsm.HsmClient
	var hsmErr error
	if config.HsmEnable {
		hsmCli, hsmErr = hsm.NewHSMClient(context.Background(), config.KeyPath, config.KeyName)
		if hsmErr != nil {
			log.Error("new hsm client fail", "hsmErr", hsmErr)
			return nil, hsmErr
		}
		rpcService.HsmClient = hsmCli
	}
	return rpcService, nil
}

func (s *RpcService) Start(ctx context.Context) error {
	go func(s *RpcService) {
		addr := fmt.Sprintf("%s:%d", s.Hostname, s.Port)
		log.Info("start rpc services", "addr", addr)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Error("Could not start tcp listener. ")
		}

		opt := grpc.MaxRecvMsgSize(MaxReceivedMessageSize)

		gs := grpc.NewServer(
			opt,
			grpc.ChainUnaryInterceptor(
				nil,
			),
		)
		reflection.Register(gs)

		wallet.RegisterWalletServiceServer(gs, s)

		log.Info("Grpc info", "port", s.Port, "address", listener.Addr())
		if err := gs.Serve(listener); err != nil {
			log.Error("Could not GRPC services")
		}
	}(s)
	return nil
}
