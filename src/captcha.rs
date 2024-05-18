use std::time::Duration;

use reqwest::{Client, ClientBuilder, Method};
use serde::Deserialize;
use uuid::Uuid;
use crate::error::SdkError;

use crate::utils::{generate_canonical_query_string, get_utc, hmac_sha256_hex, sha256};

pub struct VerifyCaptchaClient {
    pub access_key_id: String,
    pub access_key_secret: String,
    pub region: String,
    pub endpoint: String,
    pub timeout: u64,
    pub https: bool,
    pub client: Client,
}

impl VerifyCaptchaClient {
    pub fn builder() -> VerifyCaptchaClientBuilder {
        VerifyCaptchaClientBuilder {
            access_key_id: None,
            access_key_secret: None,
            region: "cn-shanghai".to_string(),
            endpoint: "captcha.cn-shanghai.aliyuncs.com".to_string(),
            timeout: 3000,
            https: true,
            danger_accept_invalid_certs: false,
        }
    }

    /// # 验证码验证接口
    /// 
    /// ## 参数
    /// - captcha_verify_param 由端上传入的验证参数。
    /// 
    /// ## 返回
    /// - [VerifyCaptchaResponse]
    ///
    /// ## 参考文档
    /// - [SendSms- 发送短信](https://api.aliyun.com/document/captcha/2023-03-05/VerifyCaptcha)
    /// - [V3版本请求体&签名机制](https://help.aliyun.com/zh/sdk/product-overview/v3-request-structure-and-signature)
    pub async fn verify_captcha(
        &self,
        captcha_verify_param: &String,
    ) -> Result<VerifyCaptchaResponse, SdkError> {
        // 初始化基本请求参数
        let host = self.endpoint.clone();
        // let region = self.region.clone();
        let action = "VerifyCaptcha".to_string();
        let version = "2023-03-05".to_string();
        let algorithm = "ACS3-HMAC-SHA256".to_string();
        let timestamp = get_utc();
        let nonce = Uuid::new_v4().to_string();

        let query_params = vec![
            ("CaptchaVerifyParam", captcha_verify_param.as_str()),
        ];

        // 步骤 1：拼接规范请求
        let method = "GET".to_string();
        // 请求路径，当资源路径为空时，使用正斜杠(/)作为canonical_uri
        let canonical_uri = "/".to_string();
        // 请求参数，当请求的查询字符串为空时，使用空字符串作为规范化查询字符串，实际上就是空白行
        let canonical_query_string = generate_canonical_query_string(&query_params);
        // 请求体，当请求正文为空时，比如GET请求，RequestPayload固定为空字符串
        let request_payload = "".to_string();
        // 计算请求体的哈希值
        let hashed_request_payload = sha256(request_payload.as_bytes());
        // 构造请求头，多个规范化消息头，按照消息头名称（小写）的字符代码顺序以升序排列后拼接在一起
        let canonical_headers = format!(
            "host:{}\nx-acs-action:{}\nx-acs-content-sha256:{}\nx-acs-date:{}\nx-acs-signature-nonce:{}\nx-acs-version:{}\n",
            host.trim(),
            action.trim(),
            hashed_request_payload.trim(),
            timestamp.trim(),
            nonce.trim(),
            version.trim()
        );
        // 已签名消息头列表，多个请求头名称（小写）按首字母升序排列并以英文分号（;）分隔
        let signed_headers = "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version";
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method,
            canonical_uri,
            canonical_query_string,
            canonical_headers,
            signed_headers,
            hashed_request_payload
        );

        // 步骤 2：拼接待签名字符串
        let hashed_canonical_request = sha256(canonical_request.as_bytes()); // 计算规范化请求的哈希值
        let string_to_sign = format!("{}\n{}", algorithm, hashed_canonical_request);

        // 步骤 3：计算签名
        let signature = hmac_sha256_hex(
            self.access_key_secret.as_bytes(),
            string_to_sign.as_bytes(),
        );

        // 步骤 4：拼接 Authorization
        let authorization = format!(
            "{} Credential={},SignedHeaders={},Signature={}",
            algorithm,
            self.access_key_id,
            signed_headers,
            signature
        );

        // 通过HttpClient发送请求
        let url = format!("{}://{}{}", if self.https { "https" } else { "http" }, host, canonical_uri);
        let request = self.client
            .request(Method::GET, url)
            .query(&query_params)
            .timeout(Duration::from_millis(self.timeout))
            .header("Authorization", authorization)
            .header("host", host)
            .header("x-acs-action", action)
            .header("x-acs-content-sha256", hashed_request_payload)
            .header("x-acs-date", timestamp)
            .header("x-acs-version", version)
            .header("x-acs-signature-nonce", nonce)
            .build()
            .unwrap();

        let response = self.client.execute(request).await?;
        let response = response.json::<VerifyCaptchaResponse>().await?;

        Ok(response)
    }
}

pub struct VerifyCaptchaClientBuilder {
    pub access_key_id: Option<String>,
    pub access_key_secret: Option<String>,
    pub region: String,
    pub endpoint: String,
    pub timeout: u64,
    pub https: bool,
    pub danger_accept_invalid_certs: bool,
}

impl VerifyCaptchaClientBuilder {
    pub fn access_key_id(mut self, access_key_id: String) -> Self {
        self.access_key_id = Some(access_key_id);
        self
    }

    pub fn access_key_secret(mut self, access_key_secret: String) -> Self {
        self.access_key_secret = Some(access_key_secret);
        self
    }

    pub fn region(mut self, region: String) -> Self {
        self.region = region;
        self
    }

    pub fn endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = endpoint;
        self
    }

    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn https(mut self, https: bool) -> Self {
        self.https = https;
        self
    }

    pub fn danger_accept_invalid_certs(mut self, danger_accept_invalid_certs: bool) -> Self {
        self.danger_accept_invalid_certs = danger_accept_invalid_certs;
        self
    }

    pub fn build(self) -> VerifyCaptchaClient {
        let access_key_id = self.access_key_id.expect("access_key_id is not set.");
        let access_key_secret = self.access_key_secret.expect("access_key_secret is not set.");
        VerifyCaptchaClient {
            access_key_id,
            access_key_secret,
            region: self.region,
            endpoint: self.endpoint,
            timeout: self.timeout,
            https: self.https,
            client: ClientBuilder::new()
                .danger_accept_invalid_certs(self.danger_accept_invalid_certs)
                .build()
                .unwrap(),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct VerifyCaptchaResponse {
    /// Id of the request
    #[serde(rename = "RequestId")]
    pub request_id: String,
    /// 请求是否成功。
    #[serde(rename = "Success")]
    pub success: bool,
    /// 响应码
    #[serde(rename = "Code")]
    pub code: String,
    /// 响应消息，若成功请求为 success
    #[serde(rename = "Message")]
    pub message: String,
    /// 返回结果
    #[serde(rename = "Result")]
    pub result: VerifyCaptchaResult,
}

#[derive(Deserialize, Debug, Clone)]
pub struct VerifyCaptchaResult {
    /// 验证结果。
    #[serde(rename = "VerifyResult")]
    pub verify_result: bool,
}