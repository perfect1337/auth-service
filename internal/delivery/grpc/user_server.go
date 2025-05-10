package grpc

import (
	"context"
	"errors"

	user "github.com/perfect1337/auth-service/internal/proto"
	"github.com/perfect1337/auth-service/internal/repository"
)

type UserServer struct {
	user.UnimplementedUserServiceServer
	repo repository.UserRepository
}

func NewUserServer(repo repository.UserRepository) *UserServer {
	return &UserServer{repo: repo}
}

func (s *UserServer) GetUsername(ctx context.Context, req *user.UserRequest) (*user.UserResponse, error) {
	// Check for nil request
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}

	// Validate user ID
	if req.UserId <= 0 {
		return nil, errors.New("invalid user ID")
	}

	// Get user from repository
	userEntity, err := s.repo.GetUserByID(ctx, int(req.UserId))
	if err != nil {
		return nil, err
	}

	// Return username
	return &user.UserResponse{
		Username: userEntity.Username,
	}, nil
}
