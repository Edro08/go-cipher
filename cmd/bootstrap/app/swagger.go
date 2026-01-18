package app

import (
	_ "GoCipher/docs"
	"fmt"
	"github.com/edro08/go-utils/config"
	"github.com/gorilla/mux"
	httpSwagger "github.com/swaggo/http-swagger"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	ckSwaggerEnable        = "server.swagger.enable"
	ckSwaggerPort          = "server.swagger.port"
	ckOpenBrowserEnable    = "server.swagger.openBrowser.enable"
	ckOpenBrowserUrl       = "server.swagger.openBrowser.url"
	ckOpenBrowserTimeSleep = "server.swagger.openBrowser.timeSleep"

	replacePort = "<port>"
)

func RunRegisterSwagger(router *mux.Router, cfg config.IConfig) {
	if !cfg.GetBool(ckSwaggerEnable) {
		return
	}

	port := cfg.GetString(ckSwaggerPort)
	if port == "" {
		return
	}

	swaggerURL := fmt.Sprintf("http://localhost:%s/swagger/doc.json", port)
	router.PathPrefix("/swagger/").Handler(
		httpSwagger.Handler(httpSwagger.URL(swaggerURL)),
	).Methods(http.MethodGet)

	if cfg.GetBool(ckOpenBrowserEnable) {
		template := cfg.GetString(ckOpenBrowserUrl)
		if !strings.Contains(template, replacePort) {
			fmt.Printf("⚠️ WARNING: '%s' is missing the %s placeholder\n", ckOpenBrowserUrl, replacePort)
			return
		}
		swaggerIndexURL := strings.Replace(template, replacePort, port, 1)
		go NewOpenBrowser(time.Duration(cfg.GetInt(ckOpenBrowserTimeSleep))*time.Second, swaggerIndexURL)
	}
}

func NewOpenBrowser(timeSleep time.Duration, url string) {
	time.Sleep(timeSleep)

	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}

	if err := exec.Command(cmd, args...).Start(); err != nil {
		fmt.Printf("Error opening browser: %v\n", err)
	}
}
