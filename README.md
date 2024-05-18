# aliyun-captcha-sdk

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

阿里云验证码2.0 sdk for rust。

## 实现

- [X] 验证码验证接口 VerifyCaptcha
- [ ] ...

## 用法

### 添加依赖

```toml
[dependencies]
aliyun-captcha-sdk = { git = "https://github.com/hi-liyan/aliyun-captcha-sdk.git" }
```

### 构建客户端

```rust
fn main() {
    let client = SmsClient::builder()
        // 阿里云 ACCESS_KEY_ID 必填
        .access_key_id("access_key_id".to_string())
        // 阿里云 ACCESS_KEY_SECRET 必填
        .access_key_secret("access_key_secret".to_string())
        // 请求超时时间 从请求发起开始直到响应结束 默认3000
        .timeout(3000)
        // 是否开启 HTTPS 默认开启
        .https(true)
        // reqwest 参数 是否忽略证书
        .danger_accept_invalid_certs(false)
        .build();
}
```

### 验证码验证 VerifyCaptcha

```rust
async fn main() {
    let response = client.verify_captcha(
        &"dsjidsjidsjkds*djsjdiskds".to_string(),
    ).await.unwrap();
    
    println!("response: {:?}", response);
}
```
