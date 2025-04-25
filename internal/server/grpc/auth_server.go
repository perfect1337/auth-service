package grpc

import (
	"context"

	"github.com/perfect1337/auth-service/internal/usecase"
	pb "github.com/perfect1337/auth-service/proto"
)

type AuthServer struct {
	pb.UnimplementedAuthServiceServer
	authUC usecase.AuthUseCase
}

func NewAuthServer(authUC usecase.AuthUseCase) *AuthServer {
	return &AuthServer{authUC: authUC}
}

func (s *AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	authResponse, err := s.authUC.Login(ctx, req.Email, req.Password)
	if err != nil {
		return nil, err
	}

	return &pb.LoginResponse{
		AccessToken:  authResponse.AccessToken,
		RefreshToken: authResponse.RefreshToken,
		User: &pb.User{
			Id:       int64(authResponse.User.ID),
			Username: authResponse.User.Username,
			Email:    authResponse.User.Email,
			Role:     authResponse.User.Role,
		},
	}, nil
}
