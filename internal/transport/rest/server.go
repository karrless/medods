package rest

import (
	"context"
	"medods/docs"
	"medods/internal/service"
	"medods/internal/transport/rest/middlewares"
	"medods/internal/transport/rest/routes"
	"medods/pkg/logger"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.uber.org/zap"
)

type ServerConfig struct {
	Host string `env:"SERVER_HOST" env-default:"localhost"`
	Port string `env:"SERVER_PORT" env-default:"8080"`
}

type Server struct {
	ctx *context.Context
	cfg ServerConfig
	r   *gin.Engine
}

func New(ctx *context.Context, cfg ServerConfig, authService *service.AuthService, debug bool) *Server {
	if !debug {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	r.Use(middlewares.WithLogger(ctx), gin.Recovery())
	r.SetTrustedProxies([]string{"127.0.0.1", cfg.Host})
	docs.SwaggerInfo.BasePath = "/"
	docs.SwaggerInfo.Host = cfg.Host + ":" + cfg.Port
	docs.SwaggerInfo.Title = "Auth API"
	docs.SwaggerInfo.Description = "API for aurh service"
	docs.SwaggerInfo.Version = "0.1.0"

	routes.AuthRoutes(ctx, r.Group("/"), authService)

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	return &Server{ctx: ctx, cfg: cfg, r: r}
}

func (s *Server) Run() error {
	logger.GetLoggerFromCtx(*s.ctx).Info("Starting server", zap.String("port", s.cfg.Port))
	return s.r.Run(":" + s.cfg.Port)
}
