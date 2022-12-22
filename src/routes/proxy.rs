use std::time::Duration;
use actix_web::{HttpResponse, Responder, web};
use actix_web::http::StatusCode;
use serde::{Deserialize};

use crate::common::WebAppData;
use crate::errors::{ServiceError, ServiceResult};

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/proxy")
            .service(web::resource("/image").route(web::get().to(get_proxy_image)))
    );
}

#[derive(Debug, Deserialize)]
pub struct ProxyImageRequest {
    url: String
}

const MAX_PROXIED_IMAGE_SIZE: usize = 10_000_000;
const MAX_PROXIED_IMAGE_TIMEOUT_SECS: u64 = 5;

// TODO: Move logic to separate proxy handler.
// TODO: Restrict route access to users only.
// TODO: Rate limit this route in bytes per time frame.
pub async fn get_proxy_image(app_data: WebAppData, query: web::Query<ProxyImageRequest>) -> ServiceResult<impl Responder> {
    println!("{:?}", query);

    // Check if image is already in our cache and send it if so.
    if let Some(cached_image) = app_data.image_cache.get(&query.url).await {
        println!("Returning cached image: {{ url: {}, size: {} }}", &query.url, cached_image.bytes.len());

        return Ok(HttpResponse::build(StatusCode::OK)
            .content_type("image/jpeg")
            .body(cached_image.bytes))
    }

    // Build a reqwest client with max connection timeout of 5 secs.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(MAX_PROXIED_IMAGE_TIMEOUT_SECS))
        .build()
        .unwrap();

    let res = client
        .get(&query.url)
        .send()
        .await
        .map_err(|_| ServiceError::BadRequest)?;

    // Verify the content-type of the response.
    if let Some(content_type) = res.headers().get("Content-Type") {
        if content_type != "image/jpeg" && content_type != "image/png" {
            return Err(ServiceError::BadRequest)
        }
    } else {
        return Err(ServiceError::BadRequest)
    }

    let image_bytes = res
        .bytes()
        .await
        .map_err(|_| ServiceError::BadRequest)?;

    // Verify that the response size does not exceed the defined max image size.
    if image_bytes.len() > MAX_PROXIED_IMAGE_SIZE {
        return Err(ServiceError::BadRequest)
    }

    // TODO: Update the cache on a separate thread, so that the client does not have to wait.
    // Update image cache.
    app_data.image_cache.set(query.url.to_string(), image_bytes.clone()).await;

    Ok(HttpResponse::build(StatusCode::OK)
        .content_type("image/jpeg")
        .body(image_bytes))
}
