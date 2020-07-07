package keysmith

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"

	"encoding/pem"
)

type SubjectStruct struct {
	CN   string `json:"cn"`
	O    string `json:"o"`
	OU   string `json:"ou"`
	L    string `json:"l"`
	ST   string `json:"st"`
	C    string `json:"c"`
	SANS string `json:"sans"`
}

type KeyBlock struct {
	KeyType     string        `json:"keyType"`
	KeySize     int           `json:"keySize"`
	SubjectInfo SubjectStruct `json:"subjectInfo"`
	KeyPEM      string        `json:"keyPEM"`
	CSRPEM      string        `json:"csrPEM"`
	CertPEM     string        `json:"certPEM"`
	HashAlg     string        `json:"hashAlg"`
	Error       string        `json:"error"`
}

func (inputKeyBlock *KeyBlock) GenerateCSR() {
	var keyBytes interface{}
	var sigAlg x509.SignatureAlgorithm
	var keyAlg x509.PublicKeyAlgorithm

	//	Defaults
	if inputKeyBlock.KeyType == "" {
		inputKeyBlock.KeyType = "RSA"
	}
	if inputKeyBlock.KeySize == 0 {
		inputKeyBlock.KeySize = 2048
	}
	if inputKeyBlock.HashAlg == "" {
		inputKeyBlock.HashAlg = "SHA256"
	}

	//	Parse and generate key (if compiled to WASM, Go uses WebCrypto for 'rand')
	if inputKeyBlock.KeyType == "RSA" {
		keyAlg = x509.RSA
		if inputKeyBlock.KeySize == 2048 {
			keyBytes, _ = rsa.GenerateKey(rand.Reader, 2048)
		} else if inputKeyBlock.KeySize == 3072 {
			keyBytes, _ = rsa.GenerateKey(rand.Reader, 3072)
		} else if inputKeyBlock.KeySize == 4096 {
			keyBytes, _ = rsa.GenerateKey(rand.Reader, 4096)
		} else {
			inputKeyBlock.Error = "Invalid RSA key size (should be 2048, 3072, 4096)"
			return
		}

		privateByes, _ := x509.MarshalPKCS8PrivateKey(keyBytes)
		inputKeyBlock.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateByes}))
	} else if inputKeyBlock.KeyType == "EC" {
		keyAlg = x509.ECDSA
		if inputKeyBlock.KeySize == 256 {
			keyBytes, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		} else if inputKeyBlock.KeySize == 384 {
			keyBytes, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		} else if inputKeyBlock.KeySize == 521 {
			keyBytes, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		} else {
			inputKeyBlock.Error = "Invalid ECC curve (should be 256, 384, 521)"
			return
		}

		privateByes, _ := x509.MarshalPKCS8PrivateKey(keyBytes)
		inputKeyBlock.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateByes}))
	} else {
		inputKeyBlock.Error = "Invalid key type"
		return
	}

	//	Hash (signature) algorithm choice
	if inputKeyBlock.HashAlg == "SHA256" {
		if inputKeyBlock.KeyType == "RSA" {
			sigAlg = x509.SHA256WithRSA
		} else {
			sigAlg = x509.ECDSAWithSHA256
		}
	} else if inputKeyBlock.HashAlg == "SHA384" {
		if inputKeyBlock.KeyType == "RSA" {
			sigAlg = x509.SHA384WithRSA
		} else {
			sigAlg = x509.ECDSAWithSHA384
		}
	} else if inputKeyBlock.HashAlg == "SHA512" {
		if inputKeyBlock.KeyType == "RSA" {
			sigAlg = x509.SHA512WithRSA
		} else {
			sigAlg = x509.ECDSAWithSHA512
		}
	} else {
		inputKeyBlock.Error = "Invalid hash algorithm"
		return
	}

	//	Prepare a template for the PKCS#10 CSR from the list of Subject details
	//	No further checking at this point (e.g. checking 'C' is ISO3166-2 two-letter)
	var inputSubjectCSR pkix.Name

	if inputKeyBlock.SubjectInfo.CN != "" {
		inputSubjectCSR.CommonName = inputKeyBlock.SubjectInfo.CN
	}
	if inputKeyBlock.SubjectInfo.O != "" {
		inputSubjectCSR.Organization = []string{inputKeyBlock.SubjectInfo.O}
	}
	if inputKeyBlock.SubjectInfo.OU != "" {
		inputSubjectCSR.OrganizationalUnit = []string{inputKeyBlock.SubjectInfo.OU}
	}
	if inputKeyBlock.SubjectInfo.L != "" {
		inputSubjectCSR.Locality = []string{inputKeyBlock.SubjectInfo.L}
	}
	if inputKeyBlock.SubjectInfo.ST != "" {
		inputSubjectCSR.Province = []string{inputKeyBlock.SubjectInfo.ST}
	}
	if inputKeyBlock.SubjectInfo.C != "" {
		inputSubjectCSR.Country = []string{inputKeyBlock.SubjectInfo.C}
	}

	certTemplate := x509.CertificateRequest{
		SignatureAlgorithm: sigAlg,
		PublicKeyAlgorithm: keyAlg,
		Subject:            inputSubjectCSR,
	}

	if inputKeyBlock.SubjectInfo.SANS != "" {
		splitCommaSeparated := strings.Replace(inputKeyBlock.SubjectInfo.SANS, ",", " ", -1)
		slicedSANS := strings.Fields(splitCommaSeparated)
		certTemplate.DNSNames = slicedSANS
	}

	finalCSRBytes, _ := x509.CreateCertificateRequest(rand.Reader, &certTemplate, keyBytes)
	inputKeyBlock.CSRPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: finalCSRBytes}))
	return
}
