use std::borrow::Cow;
use std::error;

use derive_more::{Display, Error};
use hyper::StatusCode;

use crate::databases::database;
use crate::models::torrent::MetadataError;
use crate::tracker::service::TrackerAPIError;
use crate::utils::parse_torrent::DecodeTorrentFileError;

pub type ServiceResult<V> = Result<V, ServiceError>;

#[derive(Debug, Display, PartialEq, Eq, Error)]
#[allow(dead_code)]
pub enum ServiceError {
    #[display("internal server error")]
    InternalServerError,

    #[display("This server is is closed for registration. Contact admin if this is unexpected")]
    ClosedForRegistration,

    #[display("Email is required")] //405j
    EmailMissing,
    #[display("A verified email is required")]
    VerifiedEmailMissing,
    #[display("Please enter a valid email address")] //405j
    EmailInvalid,

    #[display("The value you entered for URL is not a URL")] //405j
    NotAUrl,

    #[display("Invalid username/email or password")]
    WrongPasswordOrUsername,
    #[display("Invalid password")]
    InvalidPassword,
    #[display("Username not found")]
    UsernameNotFound,
    #[display("User not found")]
    UserNotFound,

    #[display("Account not found")]
    AccountNotFound,

    /// when the value passed contains profanity
    #[display("Can't allow profanity in usernames")]
    ProfanityError,
    /// when the value passed contains blacklisted words
    /// see [blacklist](https://github.com/shuttlecraft/The-Big-Username-Blacklist)
    #[display("Username contains blacklisted words")]
    BlacklistError,
    /// when the value passed contains characters not present
    /// in [UsernameCaseMapped](https://tools.ietf.org/html/rfc8265#page-7)
    /// profile
    #[display("username_case_mapped violation")]
    UsernameCaseMappedError,

    #[display("Password too short")]
    PasswordTooShort,
    #[display("Password too long")]
    PasswordTooLong,
    #[display("Passwords don't match")]
    PasswordsDontMatch,

    #[display("Couldn't send new password to the user")]
    FailedToSendResetPassword,

    /// when the a username is already taken
    #[display("Username not available")]
    UsernameTaken,

    #[display("Invalid username. Usernames must consist of 1-20 alphanumeric characters, dashes, or underscore")]
    UsernameInvalid,

    /// email is already taken
    #[display("Email not available")]
    EmailTaken,

    #[display("Please verify your email before logging in")]
    EmailNotVerified,

    /// when the a token name is already taken
    /// token not found
    #[display("Token not found. Please sign in.")]
    TokenNotFound,

    /// token expired
    #[display("Token expired. Please sign in again.")]
    TokenExpired,

    #[display("Token invalid.")]
    /// token invalid
    TokenInvalid,

    #[display("Uploaded torrent is not valid.")]
    InvalidTorrentFile,

    #[display("Uploaded torrent has an invalid pieces key.")]
    InvalidTorrentPiecesLength,

    #[display("Only .torrent files can be uploaded.")]
    InvalidFileType,

    #[display("Torrent title is too short.")]
    InvalidTorrentTitleLength,

    #[display("Some mandatory metadata fields are missing.")]
    MissingMandatoryMetadataFields,

    #[display("Selected category does not exist.")]
    InvalidCategory,

    #[display("Selected tag does not exist.")]
    InvalidTag,

    #[display("Unauthorized action.")]
    UnauthorizedAction,

    #[display("Unauthorized actions for guest users. Try logging in to check if you have permission to perform the action")]
    UnauthorizedActionForGuests,

    #[display("This torrent already exists in our database.")]
    InfoHashAlreadyExists,

    #[display("A torrent with the same canonical infohash already exists in our database.")]
    CanonicalInfoHashAlreadyExists,

    #[display("A torrent with the same original infohash already exists in our database.")]
    OriginalInfoHashAlreadyExists,

    #[display("This torrent title has already been used.")]
    TorrentTitleAlreadyExists,

    #[display("Could not whitelist torrent.")]
    WhitelistingError,

    #[display("Failed to send verification email.")]
    FailedToSendVerificationEmail,

    #[display("Category already exists.")]
    CategoryAlreadyExists,

    #[display("Category name cannot be empty.")]
    CategoryNameEmpty,

    #[display("Tag already exists.")]
    TagAlreadyExists,

    #[display("Tag name cannot be empty.")]
    TagNameEmpty,

    #[display("Torrent not found.")]
    TorrentNotFound,

    #[display("Category not found.")]
    CategoryNotFound,

    #[display("Tag not found.")]
    TagNotFound,

    #[display("Database error.")]
    DatabaseError,

    #[display("Authentication error, please sign in")]
    LoggedInUserNotFound,

    // Begin tracker errors
    #[display("Sorry, we have an error with our tracker connection.")]
    TrackerOffline,

    #[display("Tracker response error. The operation could not be performed.")]
    TrackerResponseError,

    #[display("Tracker unknown response. Unexpected response from tracker. For example, if it can't be parsed.")]
    TrackerUnknownResponse,

    #[display("Torrent not found in tracker.")]
    TorrentNotFoundInTracker,

    #[display("Invalid tracker API token.")]
    InvalidTrackerToken,
    // End tracker errors
}

impl From<sqlx::Error> for ServiceError {
    fn from(e: sqlx::Error) -> Self {
        eprintln!("{e:?}");

        if let Some(err) = e.as_database_error() {
            return if err.code() == Some(Cow::from("2067")) {
                if err.message().contains("torrust_torrents.info_hash") {
                    println!("info_hash already exists {}", err.message());
                    ServiceError::InfoHashAlreadyExists
                } else {
                    ServiceError::InternalServerError
                }
            } else {
                ServiceError::TorrentNotFound
            };
        }

        ServiceError::InternalServerError
    }
}

impl From<database::Error> for ServiceError {
    fn from(e: database::Error) -> Self {
        map_database_error_to_service_error(&e)
    }
}

impl From<argon2::password_hash::Error> for ServiceError {
    fn from(e: argon2::password_hash::Error) -> Self {
        eprintln!("{e}");
        ServiceError::InternalServerError
    }
}

impl From<std::io::Error> for ServiceError {
    fn from(e: std::io::Error) -> Self {
        eprintln!("{e}");
        ServiceError::InternalServerError
    }
}

impl From<Box<dyn error::Error>> for ServiceError {
    fn from(e: Box<dyn error::Error>) -> Self {
        eprintln!("{e}");
        ServiceError::InternalServerError
    }
}

impl From<serde_json::Error> for ServiceError {
    fn from(e: serde_json::Error) -> Self {
        eprintln!("{e}");
        ServiceError::InternalServerError
    }
}

impl From<MetadataError> for ServiceError {
    fn from(e: MetadataError) -> Self {
        eprintln!("{e}");
        match e {
            MetadataError::MissingTorrentTitle => ServiceError::MissingMandatoryMetadataFields,
            MetadataError::InvalidTorrentTitleLength => ServiceError::InvalidTorrentTitleLength,
        }
    }
}

impl From<DecodeTorrentFileError> for ServiceError {
    fn from(e: DecodeTorrentFileError) -> Self {
        eprintln!("{e}");
        match e {
            DecodeTorrentFileError::InvalidTorrentPiecesLength => ServiceError::InvalidTorrentTitleLength,
            DecodeTorrentFileError::CannotBencodeInfoDict
            | DecodeTorrentFileError::InvalidInfoDictionary
            | DecodeTorrentFileError::InvalidBencodeData => ServiceError::InvalidTorrentFile,
        }
    }
}

impl From<TrackerAPIError> for ServiceError {
    fn from(e: TrackerAPIError) -> Self {
        eprintln!("{e}");
        match e {
            TrackerAPIError::TrackerOffline { error: _ } => ServiceError::TrackerOffline,
            TrackerAPIError::InternalServerError | TrackerAPIError::NotFound => ServiceError::TrackerResponseError,
            TrackerAPIError::TorrentNotFound => ServiceError::TorrentNotFoundInTracker,
            TrackerAPIError::UnexpectedResponseStatus
            | TrackerAPIError::MissingResponseBody
            | TrackerAPIError::FailedToParseTrackerResponse { body: _ } => ServiceError::TrackerUnknownResponse,
            TrackerAPIError::CannotSaveUserKey => ServiceError::DatabaseError,
            TrackerAPIError::InvalidToken => ServiceError::InvalidTrackerToken,
        }
    }
}

#[must_use]
pub fn http_status_code_for_service_error(error: &ServiceError) -> StatusCode {
    #[allow(clippy::match_same_arms)]
    match error {
        ServiceError::ClosedForRegistration => StatusCode::FORBIDDEN,
        ServiceError::EmailInvalid => StatusCode::BAD_REQUEST,
        ServiceError::NotAUrl => StatusCode::BAD_REQUEST,
        ServiceError::WrongPasswordOrUsername => StatusCode::FORBIDDEN,
        ServiceError::InvalidPassword => StatusCode::FORBIDDEN,
        ServiceError::UsernameNotFound => StatusCode::NOT_FOUND,
        ServiceError::UserNotFound => StatusCode::NOT_FOUND,
        ServiceError::AccountNotFound => StatusCode::NOT_FOUND,
        ServiceError::ProfanityError => StatusCode::BAD_REQUEST,
        ServiceError::BlacklistError => StatusCode::BAD_REQUEST,
        ServiceError::UsernameCaseMappedError => StatusCode::BAD_REQUEST,
        ServiceError::PasswordTooShort => StatusCode::BAD_REQUEST,
        ServiceError::PasswordTooLong => StatusCode::BAD_REQUEST,
        ServiceError::PasswordsDontMatch => StatusCode::BAD_REQUEST,
        ServiceError::FailedToSendResetPassword => StatusCode::INTERNAL_SERVER_ERROR,
        ServiceError::UsernameTaken => StatusCode::BAD_REQUEST,
        ServiceError::UsernameInvalid => StatusCode::BAD_REQUEST,
        ServiceError::EmailTaken => StatusCode::BAD_REQUEST,
        ServiceError::EmailNotVerified => StatusCode::FORBIDDEN,
        ServiceError::TokenNotFound => StatusCode::UNAUTHORIZED,
        ServiceError::TokenExpired => StatusCode::UNAUTHORIZED,
        ServiceError::TokenInvalid => StatusCode::UNAUTHORIZED,
        ServiceError::TorrentNotFound => StatusCode::NOT_FOUND,
        ServiceError::InvalidTorrentFile => StatusCode::BAD_REQUEST,
        ServiceError::InvalidTorrentPiecesLength => StatusCode::BAD_REQUEST,
        ServiceError::InvalidFileType => StatusCode::BAD_REQUEST,
        ServiceError::InvalidTorrentTitleLength => StatusCode::BAD_REQUEST,
        ServiceError::MissingMandatoryMetadataFields => StatusCode::BAD_REQUEST,
        ServiceError::InvalidCategory => StatusCode::BAD_REQUEST,
        ServiceError::InvalidTag => StatusCode::BAD_REQUEST,
        ServiceError::UnauthorizedAction => StatusCode::FORBIDDEN,
        ServiceError::UnauthorizedActionForGuests => StatusCode::UNAUTHORIZED,
        ServiceError::InfoHashAlreadyExists => StatusCode::BAD_REQUEST,
        ServiceError::CanonicalInfoHashAlreadyExists => StatusCode::CONFLICT,
        ServiceError::OriginalInfoHashAlreadyExists => StatusCode::CONFLICT,
        ServiceError::TorrentTitleAlreadyExists => StatusCode::BAD_REQUEST,
        ServiceError::TrackerOffline => StatusCode::SERVICE_UNAVAILABLE,
        ServiceError::CategoryNameEmpty => StatusCode::BAD_REQUEST,
        ServiceError::CategoryAlreadyExists => StatusCode::BAD_REQUEST,
        ServiceError::TagNameEmpty => StatusCode::BAD_REQUEST,
        ServiceError::TagAlreadyExists => StatusCode::BAD_REQUEST,
        ServiceError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        ServiceError::EmailMissing => StatusCode::NOT_FOUND,
        ServiceError::VerifiedEmailMissing => StatusCode::NOT_FOUND,
        ServiceError::FailedToSendVerificationEmail => StatusCode::INTERNAL_SERVER_ERROR,
        ServiceError::WhitelistingError => StatusCode::INTERNAL_SERVER_ERROR,
        ServiceError::DatabaseError => StatusCode::INTERNAL_SERVER_ERROR,
        ServiceError::CategoryNotFound => StatusCode::NOT_FOUND,
        ServiceError::TagNotFound => StatusCode::NOT_FOUND,
        ServiceError::TrackerResponseError => StatusCode::INTERNAL_SERVER_ERROR,
        ServiceError::TrackerUnknownResponse => StatusCode::INTERNAL_SERVER_ERROR,
        ServiceError::TorrentNotFoundInTracker => StatusCode::NOT_FOUND,
        ServiceError::InvalidTrackerToken => StatusCode::INTERNAL_SERVER_ERROR,
        ServiceError::LoggedInUserNotFound => StatusCode::UNAUTHORIZED,
    }
}

#[must_use]
pub fn map_database_error_to_service_error(error: &database::Error) -> ServiceError {
    #[allow(clippy::match_same_arms)]
    match error {
        database::Error::Error => ServiceError::InternalServerError,
        database::Error::ErrorWithText(_) => ServiceError::InternalServerError,
        database::Error::UsernameTaken => ServiceError::UsernameTaken,
        database::Error::EmailTaken => ServiceError::EmailTaken,
        database::Error::UserNotFound => ServiceError::UserNotFound,
        database::Error::CategoryNotFound => ServiceError::InvalidCategory,
        database::Error::TagAlreadyExists => ServiceError::TagAlreadyExists,
        database::Error::TagNotFound => ServiceError::InvalidTag,
        database::Error::TorrentNotFound => ServiceError::TorrentNotFound,
        database::Error::TorrentAlreadyExists => ServiceError::InfoHashAlreadyExists,
        database::Error::TorrentTitleAlreadyExists => ServiceError::TorrentTitleAlreadyExists,
        database::Error::UnrecognizedDatabaseDriver => ServiceError::InternalServerError,
        database::Error::TorrentInfoHashNotFound => ServiceError::TorrentNotFound,
    }
}
