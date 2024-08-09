package sm

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
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
)

func GetDkmsClientByClientKeyFile(clientKeyPath, password, endpoint string) (*dedicatedkmssdk.Client, error) {
	config := &dedicatedkmsopenapi.Config{
		Protocol:      tea.String("https"),
		ClientKeyFile: tea.String(clientKeyPath),
		Password:      tea.String(password),
		Endpoint:      tea.String(endpoint),
	}
	// Init DKMS client
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
