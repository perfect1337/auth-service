package grpc

import (
	"context"

	user "github.com/perfect1337/auth-service/internal/proto"
	"github.com/perfect1337/auth-service/internal/repository"
)

type UserServer struct {
	user.UnimplementedUserServiceServer
	repo repository.Postgres
}

func NewUserServer(repo repository.Postgres) *UserServer {
	return &UserServer{repo: repo}
}

func (s *UserServer) GetUsername(ctx context.Context, req *user.UserRequest) (*user.UserResponse, error) {
	// Получаем полную информацию о пользователе
	userEntity, err := s.repo.GetUserByID(ctx, int(req.UserId))
	if err != nil {
		return nil, err
	}

	// Возвращаем только имя пользователя
	return &user.UserResponse{
		Username: userEntity.Username, // Извлекаем строку Username из структуры User
	}, nil
}
