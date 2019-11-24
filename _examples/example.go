package main

import (
	"fmt"

	"github.com/XbyOrange/xcrypt"
)

func main() {
	key := []byte("imakeywith16char")
	ciphertext, err := xcrypt.EncryptCBC(key, "datatoencrypt")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(ciphertext)
	result, err := xcrypt.DecryptCBC(key, ciphertext)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
}
