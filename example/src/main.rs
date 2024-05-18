use std::env;

use aliyun_captcha_sdk::captcha::VerifyCaptchaClient;

#[tokio::main]
async fn main() {
    let client = VerifyCaptchaClient::builder()
        .access_key_id(env::var("ACCESS_KEY_ID").unwrap())
        .access_key_secret(env::var("ACCESS_KEY_SECRET").unwrap())
        .https(false)
        .build();

    let response = client.verify_captcha(
        &"dsjidsjidsjkds*djsjdiskds".to_string(),
    ).await.unwrap();

    println!("{:?}", response);
}