package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func ServerTurnOn(router *mux.Router, serverName string, port string) {
	signalsChan := make(chan os.Signal, 1)
	errorsChan := make(chan error, 1)
	defer close(signalsChan)
	defer close(errorsChan)

	server := &http.Server{
		Handler:      router,
		Addr:         ":" + port,
		WriteTimeout: 300 * time.Second,
		ReadTimeout:  300 * time.Second,
	}

	go func() {
		fmt.Printf("🔌 [%s] is listening on port: %s\n", serverName, port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errorsChan <- err
		}
	}()

	signal.Notify(signalsChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-signalsChan:
		fmt.Printf("⚠️ WARNING: Received termination signal: %v\n", sig)
	case err := <-errorsChan:
		fmt.Printf("❌ ERROR: Server encountered an error: %v\n", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	fmt.Println("🔌 Server shutdown, bye!")
}
