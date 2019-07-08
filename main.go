package main

import (
	"crypto/elliptic"
	"flag"
	"key-generator/gen"
)

func main() {
	typ := flag.String("t", "rsa", "type: rsa or ecc")
	name := flag.String("n", "", "name: file name prefix")
	bits := flag.Int("b", 2048, "bits: 1024 or 2048")
	curve := flag.String("c", "P521", "curve: P224, P384, P256, or P521")
	flag.Parse()
	if *typ == "rsa" {
		gen.GenerateRSAKey(*bits, *name)
	} else if *typ == "ecc" {
		switch *curve {
		case "P224":
			gen.GenerateECCKey(elliptic.P224(), *name)
		case "P256":
			gen.GenerateECCKey(elliptic.P256(), *name)
		case "P384":
			gen.GenerateECCKey(elliptic.P384(), *name)
		case "P521":
			gen.GenerateECCKey(elliptic.P521(), *name)
		}
	}
}
