package main

import (
	"context"
	"crypto/tls"
	//"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"strconv"
	"net/http"
	"os"
	//"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

var (
	// Global context for Redis and HTTP operations
	ctx = context.Background()

	// Redis client for database interactions
	redisClient *redis.Client
)

// basicAuth creates a base64 encoded Basic Authentication string
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// redirectPolicyFunc adds Basic Authentication to redirected requests
func redirectPolicyFunc(req *http.Request, via []*http.Request) error {
	username, password, _ := req.BasicAuth()
	req.Header.Add("Authorization", "Basic "+basicAuth(username, password))
	return nil
}

// initRedisClient creates a secure TLS-enabled Redis client
func initRedisClient() error {
	// Get Redis connection details from environment
	redisHost := os.Getenv("REDIS_HOST")
	if redisHost == "" {
		redisHost = "redis" // Default hostname
	}
	redisPort := os.Getenv("REDIS_PORT")
	if redisPort == "" {
		redisPort = "6379" // Default port
	}
	redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort)

	// Load client certificate
	/*cert, err := tls.LoadX509KeyPair("/etc/app/certs/app.crt", "/etc/app/certs/app.key")
	if err != nil {
		return fmt.Errorf("failed to load client certificate: %v", err)
	}

	// Load CA certificate
	caCert, err := os.ReadFile("/etc/app/certs/redis.crt")
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)*/

	// Read Redis password from file
	/*passwordBytes, err := os.ReadFile("/run/secrets/redis_password")
	if err != nil {
		return fmt.Errorf("failed to read Redis password: %v", err)
	}
	redisPassword := strings.TrimSpace(string(passwordBytes))*/
	redisPassword := os.Getenv("REDIS_PASSWORD")

	// Create Redis client with TLS configuration
	redisClient = redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       0, // Default database
		/*TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		},*/
	})

	// Verify Redis connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Ping Redis to check connection with detailed logging
	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		log.Printf("Detailed Redis connection error: %v", err)
		log.Printf("Connection details - Host: %s, Port: %s", redisHost, redisPort)
		return fmt.Errorf("failed to connect to Redis at %s: %v", redisAddr, err)
	}

	log.Printf("Successfully connected to Redis at %s", redisAddr)
	return nil
}

func getRedisTTL() time.Duration {
	expSec := 0
	err := error(nil)
	expSecStr := os.Getenv("REDIS_EXP_SECONDS")
	if expSecStr != "" {
	  expSec, err = strconv.Atoi(expSecStr)
	  if err != nil {
		log.Printf("strconv err:", err)
		expSec = 300
	  }
	}
  
	return time.Duration(expSec) * time.Second
}

// getMembershipByID retrieves membership data from Redis or SAP
func getMembershipByID(c *gin.Context) {
	// Extract account ID from request
	accountId := c.Param("id")

	// Try to get data from Redis cache
	val, err := redisClient.Get(ctx, accountId).Result()
	if err != nil {
		// Handle cache miss or Redis error
		if err == redis.Nil {
			log.Printf("No cache data found for ID %s", accountId)
		} else {
			log.Printf("Redis retrieval error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Cache retrieval failed",
			})
			return
		}
	}

	// Return cached data if available
	if val != "" {
		c.JSON(http.StatusOK, val)
		return
	}

	cert, _ := tls.LoadX509KeyPair("cert.pem", "cert.key")

	ssl := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	// Prepare HTTP client for SAP request
	clientSAP := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: ssl,
		},
	}

	// Extract authentication credentials
	username, password, _ := c.Request.BasicAuth()
	servername := os.Getenv("SAP_SERVERNAME")

	// Create SAP request
	req, err := http.NewRequest("GET", servername+"/sap/rest/v1/loyalty/memberships/"+accountId, nil)
	if err != nil {
		log.Printf("Failed to create SAP request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create SAP request",
		})
		return
	}

	// Add Basic Authentication
	req.Header.Add("Authorization", "Basic "+basicAuth(username, password))

	// Send request to SAP
	resp, err := clientSAP.Do(req)
	if err != nil {
		log.Printf("SAP request failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "SAP request failed",
		})
		return
	}
	defer resp.Body.Close()

	// Read SAP response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read SAP response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to read SAP response",
		})
		return
	}

	// Convert response to string
	sb := string(body)

	// Cache SAP response in Redis
	err = redisClient.Set(ctx, accountId, sb, getRedisTTL()).Err()
	if err != nil {
		log.Printf("Failed to cache SAP response: %v", err)
		// Continue even if caching fails
	}

	// Return SAP response
	c.JSON(http.StatusOK, sb)
	log.Printf("Retrieved membership for ID: %s", accountId)
}

// invalidMembershipByID removes a membership entry from Redis cache
func invalidMembershipByID(c *gin.Context) {
	accountId := c.Param("id")
	_, err := redisClient.Del(ctx, accountId).Result()
	if err != nil {
		log.Printf("Failed to invalidate cache for ID %s: %v", accountId, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Cache invalidation failed",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Cache entry removed successfully",
	})
}

// setMembershipByID stores a membership entry in Redis cache
func setMembershipByID(c *gin.Context) {
	accountId := c.Param("id")
	
	// Read request body
	jsonData, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	// Store in Redis cache
	err = redisClient.Set(ctx, accountId, jsonData, getRedisTTL()).Err()
	if err != nil {
		log.Printf("Failed to set cache for ID %s: %v", accountId, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to store in cache",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Membership stored successfully",
	})
}

func main() {
	// Initialize Redis client with error handling
	if err := initRedisClient(); err != nil {
		log.Fatalf("Redis initialization failed: %v", err)
	}

	// Create Gin router
	router := gin.Default()

	// Define routes
	router.GET("/memberships/:id", getMembershipByID)
	router.POST("/memberships/del/:id", invalidMembershipByID)
	router.POST("/memberships/:id", setMembershipByID)

	// Start server
	log.Println("Starting server on 0.0.0.0:8089")
	router.Run("0.0.0.0:8089")
}
