package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

const NUM_REQUEST = 1_000

func main() {
	args := os.Args
	if len(args) < 2 {
		fmt.Println("no command given")
		return
	}
	switch args[1] {
	case "get":
		get()
	case "serve":
		serve()
	}
}

func get() {
	t := time.Now()
	for range NUM_REQUEST {
		_, err := http.Get("http://127.0.0.1:5882/")
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	dur := time.Since(t)
	nsPerReq := float32(dur.Nanoseconds()) / float32((NUM_REQUEST))
	fmt.Printf("made %dK requests in %s\n%.2fns/req\n%.2freq/sec\n", NUM_REQUEST/1000, dur, nsPerReq, float64(NUM_REQUEST)/dur.Seconds())
}

func serve() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello world"))
	})
	err := http.ListenAndServe(":5882", nil)
	if err != nil {
		fmt.Println(err)
		return
	}
}
