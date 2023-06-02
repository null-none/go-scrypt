# go-scrypt
Encrypt data with password

```bash
go get -u golang.org/x/crypto
go get -u https://github.com/null-none/go-scrypt
```

```go
package main

import (
	Scrypt "github.com/null-none/go-scrypt"
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"log"
	"os"
	"strings"
)


func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Enter password and text for encryption")
	fmt.Println("---------------------")
	fmt.Print("Password -> ")
	inputPassword, _ := reader.ReadString('\n')
	inputPassword = strings.Replace(inputPassword, "\n", "", -1)
	fmt.Print("Data -> ")
	inputData, _ := reader.ReadString('\n')
	inputData = strings.Replace(inputData, "\n", "", -1)

	var (
		password = []byte(inputPassword)
		data     = []byte(inputData)
	)
	ciphertext, err := Scrypt.Encrypt(password, data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ciphertext: %s\n", hex.EncodeToString(ciphertext))
	plaintext, err := Scrypt.Decrypt(password, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("plaintext: %s\n", plaintext)
  
}
```


```bash
Enter password and text for encryption
---------------------
Password -> test
Data -> test
ciphertext: bc73454392d981a41fc3e36e8c9d547028ed02524bcfb7f112c683a8ac649786f56ffa591e0527a74d679b841d3e625f96541dc170a245c5df4818233e3f3d22
plaintext: test
```
