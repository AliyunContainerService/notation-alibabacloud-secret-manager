# Alibaba Cloud Secret Manager plugin for Notation

本仓库包含 [Notation](https://notaryproject.dev/) 的 [阿里云KMS凭据管家](https://www.alibabacloud.com/help/en/kms/support/overview-6) 签名插件的实现。用户可以使用阿里云凭据管家中的私钥和证书，基于Notation社区的插件规范对指定镜像签名。

> **注意** Notary的项目文档可参考[这里](https://notaryproject.dev/docs/). 你也可以在Notary项目的 [README](https://github.com/notaryproject/.github/blob/main/README.md) 文件中了解更多关于Notary项目的信息。



## 快速开始

本文档介绍了如何使用 Alibaba Cloud Secret Manager Notation 插件对 OCI 构件进行签名和验证。


#### 插件规范兼容性

| Capability       | Compatibility                                                |
| ---------------- | ------------------------------------------------------------ |
| keySpec          | `RSA-2048`, `RSA-3072`, `EC-256`                             |
| hashAlgorithm    | `SHA-256`                                                    |
| signingAlgorithm | `RSASSA-PSS-SHA-256`                                         |
| pluginCapability | `SIGNATURE_GENERATOR.RAW`, `SIGNATURE_VERIFIER.TRUSTED_IDENTITY`, `SIGNATURE_VERIFIER.REVOCATION_CHECK` |
| signingScheme    | `notary.x509`                                                |



## 入门:



下面总结了配置 notation-alibabacloud-secret-manager 插件以及容器镜像签名和验签的步骤。

- 安装Notation [CLI](https://github.com/notaryproject/notation/releases/tag/v1.1.1)。版本 v1.1.1 已通过测试。请注意，“make install ”会根据 MacOS 环境创建插件目录结构。请根据您的操作系统更新 Makefile。然后，它会根据符号插件目录结构规范将插件复制到适当的位置。

- 本插件使用 [KMS Instance SDK](https://www.alibabacloud.com/help/en/kms/developer-reference/kms-instance-sdk-for-go/)，您需要满足以下先决条件并自定义环境变量：



| 环境变量                             | 描述                                                         |
| ------------------------------------ | ------------------------------------------------------------ |
| ALIBABA_CLOUD_ACCESS_KEY_ID          | 阿里云账户Access Key ID                                      |
| ALIBABA_CLOUD_ACCESS_KEY_SECRET      | 阿里云账号Access Secret Key                                  |
| ALIBABA_CLOUD_KMS_INSTANCE_ENDPOINT  | 指定KMS专属实例的VPC Endpoint，比如：kst-hzxxxxxxxxxx.cryptoservice.kms.aliyuncs.com |
| ALIBABA_CLOUD_KMS_CLIENTKEY_FILEPATH | 访问指定KMS专属实例应用接入点（AAP）的ClientKey凭据文件对应的本地文件路径 |
| ALIBABA_CLOUD_KMS_PASSWORD           | 指定KMS专属实例应用接入点（AAP）的密钥                       |
| ALIBABA_CLOUD_KMS_CA_FILEPATH        | 指定KMS专属实例CA证书对应的本地文件路径                      |

*注意：notation-alibabacloud-secret-manager插件支持多种Credential配置方式。更多的配置方式请参考[credentials](https://aliyuncontainerservice.github.io/ack-ram-tool/#credentials)*



## 安装



您可以通过 [Releases](https://github.com/AliyunContainerService/notation-alibabacloud-secret-manager/releases) 页面下载最新版的命令行工具，或选择基于源码构建和安装

```bash
git clone
cd notation-alibabacloud-secret-manager
make build
```



在下载或构建完成对应的plugin二进制文件后，可以在目标环境上通过执行如下的notation CLI指令完成安装：

```bash
notation plugin add --file ./notation-alibabacloud.secretmanager.plugin
```

*--file参数指向plugin二进制文件所在路径*



### 管理KMS实例

用户可以在控制台启用并管理KMS实例，请关注[启用KMS实例](https://www.alibabacloud.com/help/zh/kms/key-management-service/user-guide/manage-kms-instances)的前提条件

插件支持使用KMS实例创建并管理的或使用自签并导入KMS实例这两种类型的密钥进行签名：

### 方式1：使用KMS创建并管理密钥

用户可以在KMS服务控制台通过以下步骤[创建密钥](https://help.aliyun.com/zh/kms/key-management-service/user-guide/manage-keys-2):

1. 登录密钥管理服务控制台，在顶部菜单栏选择地域后，在左侧导航栏单击资源 > 密钥管理。

2. 在密钥管理页面，单击用户主密钥页签，实例ID选择软件密钥管理实例，单击创建密钥。

3. 在创建密钥面板，完成配置项设置，注意这里的密钥规格需要选择**非对称密钥**，密钥用途选择**SIGN/VERIFY**，密钥规则选择上文插件规范兼容性里支持的密钥规格（`RSA-2048`, `RSA-3072`, `EC-256`），然后单击确定。



### 方式2： 使用自签并导入的密钥物料

用户可以使用自签密钥并将密钥材料导入KMS实例管理。作为快速入门，本教程使用 openssl 生成私钥和证书

1. 在 KMS 控制台创建非对称密钥，请参考[步骤1](https://www.alibabacloud.com/help/zh/kms/key-management-service/user-guide/import-key-material-into-an-asymmetric-key#p-qcf-3d4-pel)

2. 下载包装公钥和导入令牌，请参考[步骤2](https://www.alibabacloud.com/help/zh/kms/key-management-service/user-guide/import-key-material-into-an-asymmetric-key#p-f9p-n7u-88m)

3. 使用包装公钥加密密钥材料，请参考[步骤3](https://www.alibabacloud.com/help/zh/kms/key-management-service/user-guide/import-key-material-into-an-asymmetric-key#p-jar-kxa-iun)

4. 导入密钥材料，请参见[步骤4](https://www.alibabacloud.com/help/zh/kms/key-management-service/user-guide/import-key-material-into-an-asymmetric-key#p-j5c-vp9-9vd)

![](./docs/import_key.png)

*用户可以使用如下命令基于步骤3中的私钥 TakPrivPkcs1.pem 和[openssl.cnf](./docs/sample_openssl.cnf) 中的 server_cert 配置获取用于验签的x509 证书，也可以使用插件在签名时自动导出证书*

```bash
openssl req -x509 -new -nodes -key TakPrivPkcs1.pem  -sha256 -days 3650 -out sign.crt -config openssl.cnf -extensions server_cert
```



## 使用Notation进行制品签名

到此我们已经完成了所有配置，让我们使用Notation CLI开始制品签名。如果您还没有下载过notation CLI工具，可以从[这里](https://github.com/notaryproject/notation/releases)获取。

```bash
notation sign --id <keyId> --plugin alibabacloud.secretmanager.plugin  <myRegistry>/<myRepo>@<digest> --plugin-config output_cert_dir=<dirPath>
```



| 参数          | 说明                                                         |
| ------------- | ------------------------------------------------------------ |
| id            | 指定的阿里云KMS实例ID                                        |
| plugin-config | 插件自定义参数，支持如下配置：<br />     output_cert_dir：签名过程中可以使用该参数基于指定的KMS密钥签发对应的x509验签证书，并以文件形式输出到参数指定文件目录下<br />     ca_certs：使用自签并导入KMS实例的密钥加签时，如果您同时使用密钥签发了X509证书，可以使用该参数指定自签证书对应的文件路径 |




## 使用Notation完成制品验签
1. 配置trust store:

   ```bash
   ./notation cert add -t ca -s ack.notation "{path-to-cert}/signer.crt"
   ```
   其中`signer.crt`是之前签名时插件输出的证书或用户指定的自签证书
2. 配置trust policy:
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
3. 制品验签：
    ```bash
    ./notation verify <myRegistry>/<myRepo>@<digest> -v