package main

import "fmt"

func main() {
	key := []byte("imakeywith16char")
	ciphertext, err := EncryptCBC(key, "datatoencrypt")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", ciphertext)
	result, err := DecryptCBC(key, ciphertext)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", result)
}
