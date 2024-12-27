package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

const NUM_REQUEST = 5_000

func main() {
	args := os.Args
	if len(args) < 2 {
		fmt.Println("no command given")
		return
	}
	switch args[1] {
	case "get":
		if len(args) < 3 {
			fmt.Println("missing target, for example: get http://127.0.0.1:3000")
			return
		}
		get(args[2])
	case "serve":
		serve()
	}
}

func get(target string) {
	t := time.Now()
	for range NUM_REQUEST {
		_, err := http.Get(target)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	dur := time.Since(t)
	usPerReq := float32(dur.Microseconds()) / float32((NUM_REQUEST))
	fmt.Printf("made %dK requests in %s\n%.2fµs/req\n%.2freq/sec\n", NUM_REQUEST/1000, dur, usPerReq, float64(NUM_REQUEST)/dur.Seconds())
}

func serve() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello world"))
	})
	err := http.ListenAndServe(":3000", nil)
	if err != nil {
		fmt.Println(err)
		return
	}
}
