use std::time::Duration;
use actix_web::{HttpResponse, Responder, web};
use actix_web::http::StatusCode;
use serde::{Deserialize};

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

pub async fn get_proxy_image(query: web::Query<ProxyImageRequest>) -> ServiceResult<impl Responder> {
    // Build a reqwest client with max connection timeout of 5 secs.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
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

    // TODO: Store image in cache.

    Ok(HttpResponse::build(StatusCode::OK)
        .content_type("image/jpeg")
        .body(image_bytes))
}
