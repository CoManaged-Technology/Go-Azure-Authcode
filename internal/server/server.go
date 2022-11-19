package server

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openmspsolutions/go-azure-authcode/internal/server/controllers"
)

type AuthServer struct {
	srv *http.Server
}

func BuildServer(port string) *AuthServer {
	router := initRouter()

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	return &AuthServer{
		srv: srv,
	}
}

func (s *AuthServer) StartServer() {
	go func() {
		// service connections
		if err := s.srv.ListenAndServe(); err != nil {
			log.Printf("listen: %s\n", err)
		}
	}()
}

func (s *AuthServer) StopServer() {
	s.srv.Shutdown(context.Background())
}

func initRouter() *gin.Engine {
	router := gin.Default()
	ms := router.Group("/ms")
	{
		// Get Token Route - Receives auth token from MS Azure App
		ms.POST("/auth", controllers.GetRefreshToken)
	}
	return router
}
