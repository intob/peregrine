package main

import (
	"fmt"
	"testing"

	"lukechampine.com/blake3"
)

func TestMakeBlake3TestVectors(t *testing.T) {
	printVector("")
	printVector("hello")
	printVector("minds and machines")
	printVector("labyrinth")
	printVector(`There are several levels of meaning which can be read from 
a strand of DNA, depending on how big the chunks are which you look at,
and how powerful a decoder you use.`)
}

func printVector(input string) {
	h := blake3.New(32, nil)
	h.Write([]byte(input))
	buf := h.Sum(nil)
	fmt.Printf("%s->%x\n", input, buf)
}
