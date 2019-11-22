# Xcrypt

## Introduction

Easy way to encrypt and decrypt strings using AES 128,192 or 256 with CBC. 

The AES algorithm has a 128-bit block size, regardless of whether you key length is 256, 192 or 128 bits.When a symmetric cipher mode requires an IV, the length of the IV must be equal to the block size of the cipher. Hence, you must always use an IV of 128 bits (16 bytes) with AES.
AES provides 128 bit, 192 bit and 256 bit of secret key size for encryption. Things to remember here is if you are selecting 128 bits for encryption, then the secret key must be of 16 bits long and 24 and 32 bits for 192 and 256 bits of key size


## How to use it

Let's see an example:

```go
import(
    "github.com/XbyOrange/xcrypt"
)
```

## Functions

`EncryptCBC`: 

CBC mode is highly recommended and it requires IV to make each message unique
- Generate a random IV and returns the encrypted(base64 encoded)

```go
key := []byte("I'm a key")
ciphertext,err := xcrypt.EncryptCBC(key, "Plain text")
if err != nil{
	fmt.Println(err)
}
fmt.Println(ciphertext)
```


`DecryptCBC`:

- Input: encrypted text(base64 encoded)
- Output: decrypted text

```go
key := []byte("I'm a key")
result, err := xcrypt.DecryptCBC(key, ciphertext)
if err != nil {
	fmt.Println(err)
}
fmt.Println(result)
```

## How to import it

### With `dep`

```bash
dep ensure -add github.com/XbyOrange/xcrypt
```

### With `go get`

```bash
go get github.com/XbyOrange/xcrypt
```

Just that! You can import it in your fantastic Go program!

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.
