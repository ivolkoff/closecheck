package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gomodule/redigo/redis"
)

var (
	Pool *redis.Pool
)

func init() {
	redisHost := os.Getenv("REDIS_HOST")
	if redisHost == "" {
		redisHost = ":6379"
	}
	Pool = newPool(redisHost)
	cleanupHook()
}

func newPool(server string) *redis.Pool {

	return &redis.Pool{

		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,

		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", server)
			if err != nil {
				return nil, err
			}
			return c, err
		},

		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			_, err := c.Do("PING")
			return err
		},
	}
}

func cleanupHook() {

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)
	signal.Notify(c, syscall.SIGKILL)
	go func() {
		<-c
		Pool.Close()
		os.Exit(0)
	}()
}

func main() {
	r1, err := Get("key1")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("key1:", string(r1))
	}

	r2, err := GetContext(context.Background(), "key1")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("key2:", string(r2))
	}

	r3, err := GetNoClose("key3")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("key3:", string(r3))
	}

	r4, err := GetContextNoClose(context.Background(), "key4")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("key4:", string(r4))
	}

	err = Set("key1", []byte("value1"))
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("key1 set to value1")
	}

}

func Get(key string) ([]byte, error) {

	conn := Pool.Get()
	defer conn.Close()

	var data []byte
	data, err := redis.Bytes(conn.Do("GET", key))
	if err != nil {
		return data, fmt.Errorf("error getting key %s: %v", key, err)
	}
	return data, err
}

func GetContext(ctx context.Context, key string) ([]byte, error) {

	conn, err := Pool.GetContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting redis connection from pool: %v", err)
	}
	defer conn.Close()

	var data []byte
	data, err = redis.Bytes(conn.Do("GET", key))
	if err != nil {
		return data, fmt.Errorf("error getting key %s: %v", key, err)
	}
	return data, err
}

func GetNoClose(key string) ([]byte, error) {

	conn := Pool.Get() // want `conn \(redis.Conn\) was not closed`

	var data []byte
	data, err := redis.Bytes(conn.Do("GET", key))
	if err != nil {
		return data, fmt.Errorf("error getting key %s: %v", key, err)
	}
	return data, err
}

func GetContextNoClose(ctx context.Context, key string) ([]byte, error) {

	conn, err := Pool.GetContext(ctx) // want `conn \(redis.Conn\) was not closed`
	if err != nil {
		return nil, fmt.Errorf("error getting redis connection from pool: %v", err)
	}

	var data []byte
	data, err = redis.Bytes(conn.Do("GET", key))
	if err != nil {
		return data, fmt.Errorf("error getting key %s: %v", key, err)
	}
	return data, err
}

func Set(key string, value []byte) error {

	conn := Pool.Get() // want `conn \(redis.Conn\) was not closed`

	_, err := conn.Do("SET", key, value)
	if err != nil {
		v := string(value)
		if len(v) > 15 {
			v = v[0:12] + "..."
		}
		return fmt.Errorf("error setting key %s to %s: %v", key, v, err)
	}
	return nil
}
