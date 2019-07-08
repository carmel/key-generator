package gen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

/*
 * 生成椭圆曲线非对称加密的私钥和公钥
 * elliptic.Curve:elliptic.P521()/elliptic.P384()/elliptic.P256()
 */
func GenerateECCKey(c elliptic.Curve, prefix string) {
	// 生成密钥
	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		fmt.Println(`Key generation failed`, err)
		return
	}
	// 保存密钥
	// x509编码
	x509PrivateKey, err := x509.MarshalECPrivateKey(privateKey)

	if err != nil {
		fmt.Println(`Private key marshal failed`, err)
		return
	}

	//pem编码编码
	block := pem.Block{
		Type:  "ecc private key",
		Bytes: x509PrivateKey,
	}

	//保存到文件中
	privateFile, _ := os.Create(prefix + "_ecc_pri.pem")
	pem.Encode(privateFile, &block)
	defer privateFile.Close()

	////////////////////保存公钥//////////////////////
	// x509编码
	x509PublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Println(`Public key marshal failed`, err)
		return
	}
	// pem编码
	publicBlock := pem.Block{
		Type:  "ecc public key",
		Bytes: x509PublicKey,
	}

	publicFile, _ := os.Create(prefix + "_ecc_pub.pem")
	defer publicFile.Close()

	pem.Encode(publicFile, &publicBlock)
}

// func TestGenECC(t *testing.T) {
// 	GenerateECCKey(elliptic.P521(), "github")
// }

func GenerateRSAKey(bits int, prefix string) {
	//////////生成私钥/////////
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		fmt.Println(`Key generation failed`, err)
		return
	}
	x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	block := pem.Block{
		Type:  "rsa private key",
		Bytes: x509PrivateKey,
	}
	//保存到文件中
	privateFile, _ := os.Create(prefix + "_rsa_pri.pem")
	pem.Encode(privateFile, &block)
	defer privateFile.Close()

	////////////生成公钥/////////
	publicKey := privateKey.PublicKey
	x509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		fmt.Println(`Public key marshal failed`, err)
		return
	}
	block = pem.Block{
		Type:  "rsa public key",
		Bytes: x509PublicKey,
	}
	//保存到文件中
	publicFile, _ := os.Create(prefix + "_rsa_pub.pem")
	pem.Encode(publicFile, &block)
	defer publicFile.Close()
}
