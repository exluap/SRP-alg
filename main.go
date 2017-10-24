/**
    * @project cryptoAlg
    * @date 24.10.2017 00:47
    * @author Nikita Zaitsev (exluap) <nickzaytsew@gmail.com>
    * @twitter https://twitter.com/exluap
    * @keybase https://keybase.io/exluap
*/

package main

import "fmt"
import "crypto/subtle"

import (
	"github.com/exluap/cryptoAlg/lib"
	
)

func main() {
	bits := 2048
	pass := []byte("password string that's too long")
	i    := []byte("foouser")


	Ih, salt, v, err := lib.Verifier(i, pass, bits)
	if err != nil {
		panic(err)
	}


	Ih = Ih
	fmt.Printf("bits=%d, I=%x\n  salt=%x\n  v=%x\n", bits, Ih, salt, v)

	c, err := srp.NewClient(i, pass, bits)

	if  err != nil {
		panic(err)
	}

	creds := c.Credentials()
	fmt.Printf("Client->Server: %s\n\n", creds)



	I, A, err := srp.ServerBegin(creds)
	if err != nil {
		panic(err)
	}



	s, err := srp.NewServer(I, salt, v, A, bits)
	if err != nil {
		panic(err)
	}


	creds = s.Credentials()

	fmt.Printf("Server->Client: %s\n\n", creds)


	m1, err := c.Generate(creds)
	if err != nil {
		panic(err)
	}





	proof, err := s.ClientOk(m1)
	if err != nil {
		panic(err)
	}


	err = c.ServerOk(proof)
	if err != nil {
		panic(err)
	}




	kc := c.RawKey()
	ks := s.RawKey()

	if 1 != subtle.ConstantTimeCompare(kc, ks) {
		panic("Keys are different!")
	}

	fmt.Printf("Client Key: %x\nServer Key: %x\n", kc, ks)
}
