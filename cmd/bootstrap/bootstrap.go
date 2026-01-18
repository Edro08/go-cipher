package bootstrap

import (
	"GoCipher/cmd/bootstrap/app"
	"fmt"
	"github.com/edro08/go-utils/config"
	"github.com/edro08/go-utils/logger"
	"github.com/gorilla/mux"
)

const (
	cfgFile = "./app.yaml"

	ckServerPort = "server.port"
	ckServerName = "server.name"
)

func Run() {
	// Load config
	cfg, err := config.NewConfig(config.Opts{File: cfgFile})
	if err != nil {
		panic(err)
	}

	// Init logger
	newLogger, err := logger.NewLogger(logger.Opts{MinLevel: logger.DEBUG, Format: logger.FormatText})
	if err != nil {
		panic(err)
	}

	// Init router
	router := mux.NewRouter()

	// Endpoints Cipher
	app.RunRestApiCipher(router, cfg, newLogger)

	// Endpoint Swagger documentation
	app.RunRegisterSwagger(router, cfg)

	// Print routes
	_ = router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		pathTemplate, errPath := route.GetPathTemplate()
		methods, errMethod := route.GetMethods()
		if errPath == nil && errMethod == nil {
			for _, method := range methods {
				fmt.Println("🌐", method, pathTemplate)
			}
		}
		return nil
	})

	// Start server
	ServerTurnOn(router, cfg.GetString(ckServerName), cfg.GetString(ckServerPort))
}
