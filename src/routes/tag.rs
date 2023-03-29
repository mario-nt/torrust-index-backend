use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};

use crate::common::WebAppData;
use crate::errors::{ServiceError, ServiceResult};
use crate::models::response::OkResponse;
use crate::models::torrent_tag::TagId;

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/tag").service(
            web::resource("")
                .route(web::post().to(add_tag))
                .route(web::delete().to(delete_tag)),
        )
    );
    cfg.service(
        web::scope("/tags").service(
            web::resource("")
                .route(web::get().to(get_tags))
        )
    );
}

pub async fn get_tags(app_data: WebAppData) -> ServiceResult<impl Responder> {
    let tags = app_data.database.get_tags().await?;

    Ok(HttpResponse::Ok().json(OkResponse { data: tags }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddTag {
    pub name: String,
}

pub async fn add_tag(req: HttpRequest, payload: web::Json<AddTag>, app_data: WebAppData) -> ServiceResult<impl Responder> {
    // check for user
    let user = app_data.auth.get_user_compact_from_request(&req).await?;

    // check if user is administrator
    if !user.administrator {
        return Err(ServiceError::Unauthorized);
    }

    app_data.database.add_torrent_tag(&payload.name).await?;

    Ok(HttpResponse::Ok().json(OkResponse {
        data: payload.name.clone(),
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteTag {
    pub tag_id: TagId,
}

pub async fn delete_tag(
    req: HttpRequest,
    payload: web::Json<DeleteTag>,
    app_data: WebAppData,
) -> ServiceResult<impl Responder> {
    // check for user
    let user = app_data.auth.get_user_compact_from_request(&req).await?;

    // check if user is administrator
    if !user.administrator {
        return Err(ServiceError::Unauthorized);
    }

    app_data.database.delete_torrent_tag(payload.tag_id).await?;

    Ok(HttpResponse::Ok().json(OkResponse {
        data: payload.tag_id,
    }))
}
