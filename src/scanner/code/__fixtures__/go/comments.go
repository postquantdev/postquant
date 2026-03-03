package main

/*
This is a block comment mentioning crypto:
rsa.GenerateKey(rand.Reader, 2048)
md5.New()
*/

// rsa.GenerateKey(rand.Reader, 2048)
// md5.New()

func main() {
	msg := "rsa.GenerateKey is vulnerable"
	_ = msg
}
