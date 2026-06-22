package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	if err := router.SetTrustedProxies(nil); err != nil {
		log.Fatalf("configure trusted proxies: %v", err)
	}
	router.Use(corsMiddleware())

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"ok":                     true,
			"intelligenceConfigured": strings.TrimSpace(os.Getenv("KASPERSKY_TIP_API_KEY")) != "",
			"kscConfigured":          kscConfigured(),
			"product":                "Kaspersky Threat Intelligence Portal + Security Center Open API",
		})
	})
	registerIntegrationRoutes(router)
	registerKSCRoutes(router)

	addr := envOrDefault("BACKEND_ADDR", ":8080")
	log.Printf("Kaspersky cloud Threat Intelligence integration listening on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatal(err)
	}
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", envOrDefault("CORS_ALLOW_ORIGIN", "http://localhost:3000"))
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
