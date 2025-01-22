use std::net::SocketAddr;
use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::info;

use crate::bootstrap::logging;
use crate::cache::image::manager::ImageCacheService;
use crate::common::AppData;
use crate::config::validator::Validator;
use crate::config::Configuration;
use crate::databases::database;
use crate::services::authentication::{DbUserAuthenticationRepository, JsonWebToken, Service};
use crate::services::authorization::{CasbinConfiguration, CasbinEnforcer};
use crate::services::category::{self, DbCategoryRepository};
use crate::services::tag::{self, DbTagRepository};
use crate::services::torrent::{
    DbCanonicalInfoHashGroupRepository, DbTorrentAnnounceUrlRepository, DbTorrentFileRepository, DbTorrentInfoRepository,
    DbTorrentListingGenerator, DbTorrentRepository, DbTorrentTagRepository,
};
use crate::services::user::{self, DbBannedUserList, DbUserProfileRepository, DbUserRepository, Repository};
use crate::services::{about, authorization, proxy, settings, torrent};
use crate::tracker::statistics_importer::StatisticsImporter;
use crate::web::api::server::signals::Halted;
use crate::web::api::server::v1::auth::Authentication;
use crate::web::api::Version;
use crate::{console, mailer, tracker, web};

pub struct Running {
    pub api_socket_addr: SocketAddr,
    pub api_server: JoinHandle<std::result::Result<(), std::io::Error>>,
    pub api_server_halt_task: tokio::sync::oneshot::Sender<Halted>,
    pub tracker_data_importer_handle: tokio::task::JoinHandle<()>,
}

/// Runs the application.
///
/// # Panics
///
/// It panics if there is an error connecting to the database.
#[allow(clippy::too_many_lines)]
pub async fn run(configuration: Configuration, api_version: &Version) -> Running {
    let threshold = configuration.settings.read().await.logging.threshold.clone();

    logging::setup(&threshold);

    log_configuration(&configuration).await;

    let configuration = Arc::new(configuration);

    // Get configuration settings needed to build the app dependencies and
    // services: main API server and tracker torrents importer.

    let settings = configuration.settings.read().await;

    settings.validate().expect("invalid settings");

    // From [database] config
    let database_connect_url = settings.database.connect_url.clone().to_string();
    // From [importer] config
    let importer_torrent_info_update_interval = settings.tracker_statistics_importer.torrent_info_update_interval;
    let importer_port = settings.tracker_statistics_importer.port;
    // From [net] config
    let config_bind_address = settings.net.bind_address;
    let opt_net_tsl = settings.net.tsl.clone();
    // Unstable config
    let unstable = settings.unstable.clone();

    // IMPORTANT: drop settings before starting server to avoid read locks that
    // leads to requests hanging.
    drop(settings);

    // Build app dependencies

    let database = Arc::new(database::connect(&database_connect_url).await.expect("Database error."));
    let json_web_token = Arc::new(JsonWebToken::new(configuration.clone()));
    let auth = Arc::new(Authentication::new(json_web_token.clone()));

    // Repositories
    let category_repository = Arc::new(DbCategoryRepository::new(database.clone()));
    let tag_repository = Arc::new(DbTagRepository::new(database.clone()));
    let user_repository: Arc<Box<dyn Repository>> = Arc::new(Box::new(DbUserRepository::new(database.clone())));
    let user_authentication_repository = Arc::new(DbUserAuthenticationRepository::new(database.clone()));
    let user_profile_repository = Arc::new(DbUserProfileRepository::new(database.clone()));
    let torrent_repository = Arc::new(DbTorrentRepository::new(database.clone()));
    let canonical_info_hash_group_repository = Arc::new(DbCanonicalInfoHashGroupRepository::new(database.clone()));
    let torrent_info_repository = Arc::new(DbTorrentInfoRepository::new(database.clone()));
    let torrent_file_repository = Arc::new(DbTorrentFileRepository::new(database.clone()));
    let torrent_announce_url_repository = Arc::new(DbTorrentAnnounceUrlRepository::new(database.clone()));
    let torrent_tag_repository = Arc::new(DbTorrentTagRepository::new(database.clone()));
    let torrent_listing_generator = Arc::new(DbTorrentListingGenerator::new(database.clone()));
    let banned_user_list = Arc::new(DbBannedUserList::new(database.clone()));
    let casbin_enforcer = Arc::new(
        if let Some(casbin) = unstable
            .as_ref()
            .and_then(|u| u.auth.as_ref())
            .and_then(|auth| auth.casbin.as_ref())
        {
            CasbinEnforcer::with_configuration(CasbinConfiguration::new(&casbin.model, &casbin.policy)).await
        } else {
            CasbinEnforcer::with_default_configuration().await
        },
    );

    // Services
    let authorization_service = Arc::new(authorization::Service::new(user_repository.clone(), casbin_enforcer.clone()));
    let tracker_service = Arc::new(tracker::service::Service::new(configuration.clone(), database.clone()).await);
    let tracker_statistics_importer =
        Arc::new(StatisticsImporter::new(configuration.clone(), tracker_service.clone(), database.clone()).await);
    let mailer_service = Arc::new(mailer::Service::new(configuration.clone()).await);
    let image_cache_service: Arc<ImageCacheService> = Arc::new(ImageCacheService::new(configuration.clone()).await);
    let category_service = Arc::new(category::Service::new(
        category_repository.clone(),
        authorization_service.clone(),
    ));
    let tag_service = Arc::new(tag::Service::new(tag_repository.clone(), authorization_service.clone()));
    let proxy_service = Arc::new(proxy::Service::new(
        image_cache_service.clone(),
        authorization_service.clone(),
    ));
    let settings_service = Arc::new(settings::Service::new(configuration.clone(), authorization_service.clone()));
    let torrent_index = Arc::new(torrent::Index::new(
        configuration.clone(),
        tracker_statistics_importer.clone(),
        tracker_service.clone(),
        user_repository.clone(),
        category_repository.clone(),
        torrent_repository.clone(),
        canonical_info_hash_group_repository.clone(),
        torrent_info_repository.clone(),
        torrent_file_repository.clone(),
        torrent_announce_url_repository.clone(),
        torrent_tag_repository.clone(),
        torrent_listing_generator.clone(),
        authorization_service.clone(),
    ));
    let registration_service = Arc::new(user::RegistrationService::new(
        configuration.clone(),
        mailer_service.clone(),
        user_repository.clone(),
        user_profile_repository.clone(),
    ));
    let profile_service = Arc::new(user::ProfileService::new(
        configuration.clone(),
        user_authentication_repository.clone(),
        authorization_service.clone(),
    ));
    let ban_service = Arc::new(user::BanService::new(
        user_profile_repository.clone(),
        banned_user_list.clone(),
        authorization_service.clone(),
    ));
    let authentication_service = Arc::new(Service::new(
        configuration.clone(),
        json_web_token.clone(),
        user_repository.clone(),
        user_profile_repository.clone(),
        user_authentication_repository.clone(),
    ));

    let about_service = Arc::new(about::Service::new(authorization_service.clone()));

    let listing_service = Arc::new(user::ListingService::new(
        configuration.clone(),
        user_profile_repository.clone(),
        authorization_service.clone(),
    ))
    .clone();

    // Build app container

    let app_data = Arc::new(AppData::new(
        configuration.clone(),
        database.clone(),
        json_web_token.clone(),
        auth.clone(),
        authentication_service,
        tracker_service.clone(),
        tracker_statistics_importer.clone(),
        mailer_service,
        image_cache_service,
        category_repository,
        tag_repository,
        user_repository,
        user_authentication_repository,
        user_profile_repository,
        torrent_repository,
        canonical_info_hash_group_repository,
        torrent_info_repository,
        torrent_file_repository,
        torrent_announce_url_repository,
        torrent_tag_repository,
        torrent_listing_generator,
        banned_user_list,
        category_service,
        tag_service,
        proxy_service,
        settings_service,
        torrent_index,
        registration_service,
        profile_service,
        ban_service,
        about_service,
        listing_service,
    ));

    // Start cronjob to import tracker torrent data and updating
    // seeders and leechers info.
    let tracker_statistics_importer_handle = console::cronjobs::tracker_statistics_importer::start(
        importer_port,
        importer_torrent_info_update_interval,
        &tracker_statistics_importer,
    );

    // Start API server
    let running_api = web::api::start(app_data, config_bind_address, opt_net_tsl, api_version).await;

    // Full running application
    Running {
        api_socket_addr: running_api.socket_addr,
        api_server: running_api.task,
        api_server_halt_task: running_api.halt_task,
        tracker_data_importer_handle: tracker_statistics_importer_handle,
    }
}

/// It logs the final configuration removing secrets.
async fn log_configuration(configuration: &Configuration) {
    let mut setting = configuration.get_all().await.clone();
    setting.remove_secrets();
    info!("Configuration:\n{}", setting.to_json());
}
