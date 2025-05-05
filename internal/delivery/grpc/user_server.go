package grpc

import (
	"context"

	user "github.com/perfect1337/auth-service/internal/proto"
	"github.com/perfect1337/auth-service/internal/repository"
)

type UserServer struct {
	user.UnimplementedUserServiceServer // Важно: встраиваем стандартную реализацию
	repo                                repository.AuthRepository
}

func NewUserServer(repo repository.AuthRepository) *UserServer {
	return &UserServer{repo: repo}
}

// GetUsername - реализация метода из proto-файла
func (s *UserServer) GetUsername(ctx context.Context, req *user.UserRequest) (*user.UserResponse, error) {
	username, err := s.repo.GetUsernameByID(ctx, int(req.UserId))
	if err != nil {
		return nil, err
	}

	return &user.UserResponse{
		Username: username,
	}, nil
}
