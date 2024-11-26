package sm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/internal/log"
	"github.com/alibabacloud-go/tea/tea"
	dedicatedkmsopenapi "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/openapi"
	dedicatedkmssdk "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/sdk"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
)

const (
	KMS_RSA_2048 = "RSA_2048"
	KMS_RSA_3072 = "RSA_3072"
	KMS_RSA_4096 = "RSA_4096"
	KMS_EC_P256  = "EC_P256"
	//sign algorithm supported by KMS
	KMS_ALG_RSA_PSS_SHA_256   = "RSA_PSS_SHA_256"
	KMS_ALG_RSA_PKCS1_SHA_256 = "RSA_PKCS1_SHA_256"

	NOTATION_CN    = "notation"
	SignerCertName = "signer.crt"
)

type KmsPrivateKeySigner struct {
	client    *dedicatedkmssdk.Client
	publicKey crypto.PublicKey
	keyId     string
	algorithm string
}

func (ks *KmsPrivateKeySigner) Public() crypto.PublicKey {
	return ks.publicKey
}

func (ks *KmsPrivateKeySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	request := &dedicatedkmssdk.SignRequest{
		KeyId:       tea.String(ks.keyId),
		Message:     digest,
		MessageType: tea.String("DIGEST"),
		Algorithm:   tea.String(ks.algorithm),
	}
	resp, err := ks.client.Sign(request)
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}

func genSerialNum() (*big.Int, error) {
	serialNumLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialNumLimit)
	if err != nil {
		return nil, fmt.Errorf("serial number generation failure (%v)", err)
	}
	return serialNum, nil
}

func GetCertDataFromKey(dkmsClient *dedicatedkmssdk.Client, pub *rsa.PublicKey, keyId string) ([]byte, error) {
	//init csr subject
	subject := pkix.Name{
		Country:            []string{"CN"},
		Organization:       []string{"AlibabaCloud"},
		OrganizationalUnit: []string{"Ack"},
		CommonName:         NOTATION_CN,
	}

	//Create kms service signer object
	priv := &KmsPrivateKeySigner{
		client:    dkmsClient,              //kms client
		keyId:     keyId,                   //kms instance asymmetric key Id
		publicKey: pub,                     //kms instance asymmetric public key
		algorithm: KMS_ALG_RSA_PSS_SHA_256, //kms instance signing algorithm, RSA_PKCS1_SHA_256 is not conform with notation specification
	}

	serialNum, err := genSerialNum()
	if err != nil {
		log.Logger.Errorf("Failed to generate serail number, err %v", err)
		return nil, err
	}

	// Create a new certificate template
	template := x509.Certificate{
		SerialNumber:       serialNum,
		Subject:            subject,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		IsCA:               false,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.SHA256WithRSAPSS, //only support RSA_PSS_SHA_256 here
	}

	// Create the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		log.Logger.Errorf("Failed to generate certificate from key %s, err %v", keyId, err)
		return nil, err
	}
	return certBytes, nil
}

func GetPublicKey(client *dedicatedkmssdk.Client, keyId string) (*rsa.PublicKey, error) {
	request := &dedicatedkmssdk.GetPublicKeyRequest{
		KeyId: tea.String(keyId),
	}
	response, err := client.GetPublicKey(request)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(*response.PublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	//return rsa public key
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New(fmt.Sprintf("unsupport public key type %T", pub))
	}

	return rsaPub, nil
}

// CertDataOutput perisist certificate data to file
func CertDataOutput(certData []byte, dir string) error {
	if len(dir) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		dir = cwd
	}
	crtPath := filepath.Join(dir, SignerCertName)
	certFile, err := os.Create(crtPath)
	if err != nil {
		log.Logger.Errorf("Error creating signer certificate file:", err)
		return err
	}
	defer certFile.Close()
	return pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certData})
}

func GetDkmsClientByClientKeyFile(clientKeyPath, password, endpoint string) (*dedicatedkmssdk.Client, error) {
	// 创建DKMS Client配置
	config := &dedicatedkmsopenapi.Config{
		Protocol: tea.String("https"),
		// 请替换为您在KMS应用管理获取的ClientKey文件的路径
		ClientKeyFile: tea.String(clientKeyPath),
		// 请替换为您在KMS应用管理创建ClientKey时输入的加密口令
		Password: tea.String(password),
		// 请替换为您实际的专属KMS实例服务地址(不包括协议头https://)
		Endpoint: tea.String(endpoint),
	}
	// 创建DKMS Client对象
	client, err := dedicatedkmssdk.NewClient(config)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func ParseCertificates(keyStr string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	block, rest := pem.Decode([]byte(keyStr))
	for block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		block, rest = pem.Decode(rest)
	}
	return certs, nil
}

func SwitchKeySpec(kmsKeySpec string) (plugin.KeySpec, error) {
	switch kmsKeySpec {
	case KMS_RSA_2048:
		return plugin.KeySpecRSA2048, nil
	case KMS_RSA_3072:
		return plugin.KeySpecRSA3072, nil
	case KMS_RSA_4096:
		return plugin.KeySpecRSA4096, nil
	case KMS_EC_P256:
		return plugin.KeySpecEC256, nil
	}
	return "", errors.New(fmt.Sprintf("unsupport key spec %s", kmsKeySpec))
}
