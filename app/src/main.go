package main

import (
	"context"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

var (
	ctx         = context.Background()
	redisClient = redis.NewClient(&redis.Options{
		Addr:     "redis:6379",                // Replace with your Redis server address
		Password: os.Getenv("REDIS_PASSWORD"), // No password for local development
		DB:       0,                           // Default DB
	})
)

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func redirectPolicyFunc(req *http.Request, via []*http.Request) error {
	username, password, _ := req.BasicAuth()
	req.Header.Add("Authorization", "Basic "+basicAuth(username, password))
	return nil
}

func getRedisClient() *redis.Client {
	// Connect to Redis
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // Replace with your Redis server address
		Password: "",               // No password for local development
		DB:       0,                // Default DB
	})

	// Ping the Redis server to check the connection
	_, err := client.Ping(ctx).Result()
	if err != nil {
		log.Printf("Error connecting to Redis:", err)
		return nil
	}
	return client
}

func getMembershipByID(c *gin.Context) {
	accountId := c.Param("id")
	val, err := redisClient.Get(ctx, accountId).Result()
	if err != nil {
		log.Printf("Error connecting to redis:", err)
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	if val != "" {
		//Возвращаем ответ
		c.JSON(http.StatusOK, val)
		return
	}

	//Иначе запрашиваем у SAP
	client := &http.Client{
		//Jar: cookieJar,
		//CheckRedirect: redirectPolicyFunc,
	}

	username, password, _ := c.Request.BasicAuth()
	servername := os.Getenv("SAP_SERVERNAME")

	req, err := http.NewRequest("GET", servername+"sap/rest/v1/loyalty/memberships/"+accountId, nil)
	req.Header.Add("Authorization", "Basic "+basicAuth(username, password))
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error getting data from sap:", err)
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	//We Read the response body on the line below.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("No data:", err)
		c.JSON(http.StatusInternalServerError, err)\
		return
	}
	//Convert the body to type string
	sb := string(body)

	err = redisClient.Set(ctx, accountId, sb, 300).Err()
	if err != nil {
		log.Printf("Error setting data to redis:", err)
		//Хотя бы вернём ответ
		//c.JSON(http.StatusInternalServerError, err)
	}
	//Возвращаем ответ
	c.JSON(http.StatusOK, sb)

	log.Printf(sb)
}
func invalidMembershipByID(c *gin.Context) {
	accountId := c.Param("id")
	_, err := redisClient.Del(ctx, accountId).Result() // Remove the cache entry
	if err != nil {
		log.Printf("Error invaidating redis data:", err)
		c.JSON(http.StatusInternalServerError, err)
	}
}
func setMembershipByID(c *gin.Context) {
	accountId := c.Param("id")
	jsonData, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Printf("Error getting body from request:", err)
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	err = redisClient.Set(ctx, accountId, jsonData, 300).Err()
	if err != nil {
		log.Printf("Error setting data to redis:", err)
		c.JSON(http.StatusInternalServerError, err)
	}
}

func main() {

	router := gin.Default()
	router.GET("/memberships/:id", getMembershipByID)
	router.POST("/memberships/del/:id", invalidMembershipByID) //?
	router.POST("/memberships/:id", setMembershipByID)

	router.Run("0.0.0.0:8089")
}
