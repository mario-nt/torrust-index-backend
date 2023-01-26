use actix_web::{HttpRequest, HttpResponse, Responder, web};
use actix_web::http::StatusCode;
use serde::{Deserialize};

use crate::cache;
use crate::common::WebAppData;
use crate::errors::{ServiceError, ServiceResult};

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/proxy")
            .service(web::resource("/image")
                .route(web::get().to(get_proxy_image)))
    );
}

#[derive(Debug, Deserialize)]
pub struct ProxyImageRequest {
    url: String
}

// TODO: Restrict route access to users only.
// TODO: Rate limit this route in bytes per time frame.
pub async fn get_proxy_image(req: HttpRequest, app_data: WebAppData, query: web::Query<ProxyImageRequest>) -> ServiceResult<impl Responder> {
    println!("{:?}", query);

    // check for user
    let user = app_data.auth.get_user_compact_from_request(&req).await?;

    let image_bytes = app_data.image_cache_manager.get_image_by_url(&user.user_id, &query.url).await?;

    Ok(HttpResponse::build(StatusCode::OK)
        .content_type("image/jpeg")
        .body(image_bytes))
}

impl From<cache::image::manager::Error> for ServiceError {
    fn from(_value: cache::image::manager::Error) -> Self {
        ServiceError::BadRequest
    }
}
