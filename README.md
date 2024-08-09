
# Alibaba Cloud Secret Manager plugin for Notation

This repository contains the implementation of the [Alibaba Cloud Secret Manager](https://www.alibabacloud.com/help/en/kms/support/overview-6) signing plugin for [Notation](https://notaryproject.dev/). This project is still in early development status.

> **Note** The Notary Project documentation is available [here](https://notaryproject.dev/docs/). You can also find the Notary Project [README](https://github.com/notaryproject/.github/blob/main/README.md) to learn about the overall Notary Project.

## Quick start

This document demonstrates how to sign and verify an OCI artifact with Alibaba Cloud Secret Manager plugin for Notation.


#### Plugin Spec Compatibility

| Capability            | Compatibility                                                |
| --------------------- | ------------------------------------------------------------ |
| keySpec               | `RSA-2048`, `RSA-3072`, `EC-256`      |
| hashAlgorithm         | `SHA-256`                                                    |
| signingAlgorithm      | `RSASSA-PSS-SHA-256`, `ECDSA-SHA-256`                        |
| pluginCapability      | `SIGNATURE_GENERATOR.RAW`, `SIGNATURE_VERIFIER.TRUSTED_IDENTITY`, `SIGNATURE_VERIFIER.REVOCATION_CHECK` |
| signingScheme         | `notary.x509`                                                |



## Getting Started:

The following summarizes the steps to configure the notation-alibabacloud-secret-manager plugin and sign and verify a container image. The following steps are based off of the Notation hello-signing [example](https://github.com/notaryproject/notation-plugin-framework-go/tree/main/example).

- Install notation [CLI](https://github.com/notaryproject/notation/releases/tag/v1.1.1). Version v1.1.1 has been tested. Note that `make install` creates the plugin directory structure based on a MacOS environment. Update the Makefile based on your OS. It then copies the plugin to the appropriate location based on the notation plugin directory structure spec.

- This plugin leverages the [KMS Instance SDK](https://www.alibabacloud.com/help/en/kms/developer-reference/kms-instance-sdk-for-go/), which means you'll need to meet the pre-requisites and customize the environment as follows：

| Env            | Description                                                |
| --------------------- | ------------------------------------------------------------ |
| ALIBABA_CLOUD_ACCESS_KEY_ID      | Alibaba Cloud Account Access Key ID |
| ALIBABA_CLOUD_ACCESS_KEY_SECRET         | Alibaba Cloud Account Secret Access Key                                                    |
| ALIBABA_CLOUD_KMS_INSTANCE_ENDPOINT      | VPC Endpoint of the Dedicated KMS Instance, for example, kst-hzxxxxxxxxxx.cryptoservice.kms.aliyuncs.com               |
| ALIBABA_CLOUD_KMS_CLIENTKEY_FILEPATH      | Local File Path of the ClientKey Credential for the Dedicated KMS Instance Application Access Point (AAP) |
| ALIBABA_CLOUD_KMS_PASSWORD | Password for the Dedicated KMS Instance Application Access Point (AAP) |
| ALIBABA_CLOUD_KMS_CA_FILEPATH         | Local Path of the CA Certificate for the Dedicated KMS Instance                                              |

*Note: the notation-alibabacloud-secret-manager plugin supports various Credential configuration methods. For more details, please refer to [credentials](https://aliyuncontainerservice.github.io/ack-ram-tool/#credentials)*


## Installation

Install the notation-alibabacloud-secret-manager plugin for remote signing and verification, using the `notation plugin install` command:

#### Build and Install from Source

```bash
git clone
cd notation-alibabacloud-secret-manager
make build
```
## Generate and import the keypair meterial

A user can bring their own private key and certificate. As a quick start, this tutorial is using openssl to generate a private key and a certificate

1. Create an asymmetric key in KMS console, please refer to [step1](https://www.alibabacloud.com/help/en/kms/user-guide/import-key-material-into-an-asymmetric-key#p-qcf-3d4-pel)
2. Download a wrapping public key and an import token, please refer to [step2](https://www.alibabacloud.com/help/en/kms/user-guide/import-key-material-into-an-asymmetric-key#p-f9p-n7u-88m)
3. Use the wrapping public key to encrypt key material, please refer to [step3](https://www.alibabacloud.com/help/en/kms/user-guide/import-key-material-into-an-asymmetric-key#p-jar-kxa-iun)
4. Import key material, please refer to [step4](https://www.alibabacloud.com/help/en/kms/user-guide/import-key-material-into-an-asymmetric-key#p-j5c-vp9-9vd)
   ![](./docs/import_key.png)

5. Create an x509 certificate based on the private key TakPrivPkcs1.pem from step 3 above and the server_cert configuration in [openssl.cnf]((./docs/import_key.png)).
```bash
openssl req -x509 -new -nodes -key TakPrivPkcs1.pem  -sha256 -days 3650 -out sign.crt -config openssl.cnf -extensions server_cert
```


## Sign an artifact using Notation
Now we've done all the configurations. Let's sign an artifact using Notation. (If you haven't done so, download notation from [here](https://github.com/notaryproject/notation/releases).)
```bash
notation sign --id <keyId> --plugin alibabacloud.secretmanager.plugin  <myRegistry>/<myRepo>@<digest> --plugin-config ca_certs=<certPath>
```
Note: the `--id` should be identical to your specific key id in Alibaba Cloud KMS Service instance and the  `ca_certs` in ` --plugin-config` should  be identical to the file path of the x509 certificate generated in step 5 above.


## Verify the artifact using Notation
1. Configure trust store.
    ```bash
    ./notation cert add -t ca -s myStore "{path-to-cert}/sign.crt"
    ```
   where `sign.crt` is the cert generated in the previous step.
2. Configure the trust policy.
    ```bash 
    cat <<EOF > ./trustpolicy.json
    {
        "version": "1.0",
        "trustPolicies": [
            {
                "name": "acr-hangzhou-images",
                "registryScopes": [ "<myRegistry>/<myRepo>" ],
                "signatureVerification": {
                    "level" : "strict"
                },
                "trustStores": [ "ca:ack.notation" ],
                "trustedIdentities": [
                    "*"
                ]
            }
        ]
    }
    EOF
    ```
    ```bash
    ./notation policy import ./trustpolicy.json
    ```
3. Verify the artifact
    ```bash
    ./notation verify <myRegistry>/<myRepo>@<digest> -v

