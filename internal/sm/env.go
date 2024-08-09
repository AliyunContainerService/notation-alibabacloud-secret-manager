package sm

import (
	"os"
)

const (
	envInstanceEndpoint = "ALIBABA_CLOUD_KMS_INSTANCE_ENDPOINT"
	envClientKeyFile    = "ALIBABA_CLOUD_KMS_CLIENTKEY_FILEPATH"
	envKMSPassword      = "ALIBABA_CLOUD_KMS_PASSWORD"
	envKMSCAFile        = "ALIBABA_CLOUD_KMS_CA_FILEPATH"
	envKMSRegionId      = "ALIBABA_CLOUD_KMS_REGION_ID"
	defaultRegionId     = "cn-hangzhou"
)

var (
	instanceEndpointEnvs = []string{
		envInstanceEndpoint,
	}
	clientKeyFileEnvs = []string{
		envClientKeyFile,
	}
	kmsPasswordEnvs = []string{
		envKMSPassword,
	}
	kmsCAFileEnvs = []string{
		envKMSCAFile,
	}
	kmsRegionId = []string{
		envKMSRegionId,
	}
)

func GetInstanceEndpoint() string {
	return getEnvsValue(instanceEndpointEnvs)
}

func GetClientKey() string {
	return getEnvsValue(clientKeyFileEnvs)
}

func GetKMSPassword() string {
	return getEnvsValue(kmsPasswordEnvs)
}

func GetKMSCAFile() string {
	return getEnvsValue(kmsCAFileEnvs)
}

func GetKMSRegionId() string {
	regionId := getEnvsValue(kmsRegionId)
	if regionId == "" {
		return defaultRegionId
	}
	return regionId
}

func getEnvsValue(keys []string) string {
	for _, key := range keys {
		v := os.Getenv(key)
		if v != "" {
			return v
		}
	}
	return ""
}
