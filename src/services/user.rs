//! User services.
use std::sync::Arc;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use async_trait::async_trait;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
#[cfg(test)]
use mockall::automock;
use pbkdf2::password_hash::rand_core::OsRng;
use rand::seq::IteratorRandom;
use serde_derive::Deserialize;
use tracing::{debug, info};

use super::authentication::DbUserAuthenticationRepository;
use super::authorization::{self, ACTION};
use crate::config::v2::auth::Auth;
use crate::config::{Configuration, PasswordConstraints};
use crate::databases::database::{Database, Error};
use crate::errors::ServiceError;
use crate::mailer;
use crate::mailer::VerifyClaims;
use crate::models::response::UserProfilesResponse;
use crate::models::user::{UserCompact, UserId, UserProfile, Username};
use crate::services::authentication::verify_password;
use crate::utils::validation::validate_email_address;
use crate::web::api::server::v1::contexts::user::forms::{ChangePasswordForm, RegistrationForm};

/// Since user email could be optional, we need a way to represent "no email"
/// in the database. This function returns the string that should be used for
/// that purpose.
fn no_email() -> String {
    String::new()
}

/// User request to generate a user profile listing.
#[derive(Debug, Deserialize)]
pub struct ListingRequest {
    pub page_size: Option<u8>,
    pub page: Option<u32>,
}

/// Internal specification for user profiles listings.
#[derive(Debug, Deserialize)]
pub struct ListingSpecification {
    pub offset: u64,
    pub page_size: u8,
}

pub struct RegistrationService {
    configuration: Arc<Configuration>,
    mailer: Arc<mailer::Service>,
    user_repository: Arc<Box<dyn Repository>>,
    user_profile_repository: Arc<DbUserProfileRepository>,
}

impl RegistrationService {
    #[must_use]
    pub fn new(
        configuration: Arc<Configuration>,
        mailer: Arc<mailer::Service>,
        user_repository: Arc<Box<dyn Repository>>,
        user_profile_repository: Arc<DbUserProfileRepository>,
    ) -> Self {
        Self {
            configuration,
            mailer,
            user_repository,
            user_profile_repository,
        }
    }

    /// It registers a new user.
    ///
    /// # Errors
    ///
    /// This function will return a:
    ///
    /// * `ServiceError::EmailMissing` if email is required, but missing.
    /// * `ServiceError::EmailInvalid` if supplied email is badly formatted.
    /// * `ServiceError::PasswordsDontMatch` if the supplied passwords do not match.
    /// * `ServiceError::PasswordTooShort` if the supplied password is too short.
    /// * `ServiceError::PasswordTooLong` if the supplied password is too long.
    /// * `ServiceError::UsernameInvalid` if the supplied username is badly formatted.
    /// * `ServiceError::FailedToSendVerificationEmail` if unable to send the required verification email.
    /// * An error if unable to successfully hash the password.
    /// * An error if unable to insert user into the database.
    ///
    /// # Panics
    ///
    /// This function will panic if the email is required, but missing.
    pub async fn register_user(&self, registration_form: &RegistrationForm, api_base_url: &str) -> Result<UserId, ServiceError> {
        info!("registering user: {}", registration_form.username);

        let settings = self.configuration.settings.read().await;

        match &settings.registration {
            Some(registration) => {
                let Ok(username) = registration_form.username.parse::<Username>() else {
                    return Err(ServiceError::UsernameInvalid);
                };

                let opt_email = match &registration.email {
                    Some(email) => {
                        if email.required && registration_form.email.is_none() {
                            return Err(ServiceError::EmailMissing);
                        }
                        match &registration_form.email {
                            Some(email) => {
                                if email.trim() == String::new() {
                                    None
                                } else {
                                    Some(email.clone())
                                }
                            }
                            None => None,
                        }
                    }
                    None => None,
                };

                if let Some(email) = &opt_email {
                    if !validate_email_address(email) {
                        return Err(ServiceError::EmailInvalid);
                    }
                }

                let password_constraints = PasswordConstraints {
                    min_password_length: settings.auth.password_constraints.min_password_length,
                    max_password_length: settings.auth.password_constraints.max_password_length,
                };

                validate_password_constraints(
                    &registration_form.password,
                    &registration_form.confirm_password,
                    &password_constraints,
                )?;

                let password_hash = hash_password(&registration_form.password)?;

                let user_id = self
                    .user_repository
                    .add(
                        &username.to_string(),
                        &opt_email.clone().unwrap_or(no_email()),
                        &password_hash,
                    )
                    .await?;

                // If this is the first created account, give administrator rights
                if user_id == 1 {
                    drop(self.user_repository.grant_admin_role(&user_id).await);
                }

                if let Some(email) = &registration.email {
                    if email.verification_required {
                        // Email verification is enabled
                        if let Some(email) = opt_email {
                            let mail_res = self
                                .mailer
                                .send_verification_mail(&email, &registration_form.username, user_id, api_base_url)
                                .await;

                            if mail_res.is_err() {
                                drop(self.user_repository.delete(&user_id).await);
                                return Err(ServiceError::FailedToSendVerificationEmail);
                            }
                        }
                    }
                }

                Ok(user_id)
            }
            None => Err(ServiceError::ClosedForRegistration),
        }
    }

    /// It verifies the email address of a user via the token sent to the
    /// user's email.
    ///
    /// # Errors
    ///
    /// This function will return a `ServiceError::DatabaseError` if unable to
    /// update the user's email verification status.
    pub async fn verify_email(&self, token: &str) -> Result<bool, ServiceError> {
        let settings = self.configuration.settings.read().await;

        let token_data = match decode::<VerifyClaims>(
            token,
            &DecodingKey::from_secret(settings.auth.user_claim_token_pepper.as_bytes()),
            &Validation::new(Algorithm::HS256),
        ) {
            Ok(token_data) => {
                if !token_data.claims.iss.eq("email-verification") {
                    return Ok(false);
                }

                token_data.claims
            }
            Err(_) => return Ok(false),
        };

        drop(settings);

        let user_id = token_data.sub;

        if self.user_profile_repository.verify_email(&user_id).await.is_err() {
            return Err(ServiceError::DatabaseError);
        };

        Ok(true)
    }
}

pub struct ProfileService {
    configuration: Arc<Configuration>,
    user_authentication_repository: Arc<DbUserAuthenticationRepository>,
    authorization_service: Arc<authorization::Service>,
}

impl ProfileService {
    #[must_use]
    pub fn new(
        configuration: Arc<Configuration>,
        user_repository: Arc<DbUserAuthenticationRepository>,
        authorization_service: Arc<authorization::Service>,
    ) -> Self {
        Self {
            configuration,
            user_authentication_repository: user_repository,
            authorization_service,
        }
    }

    /// It registers a new user.
    ///
    /// # Errors
    ///
    /// This function will return a:
    ///
    /// * `ServiceError::InvalidPassword` if the current password supplied is invalid.
    /// * `ServiceError::PasswordsDontMatch` if the supplied passwords do not match.
    /// * `ServiceError::PasswordTooShort` if the supplied password is too short.
    /// * `ServiceError::PasswordTooLong` if the supplied password is too long.
    /// * An error if unable to successfully hash the password.
    /// * An error if unable to change the password in the database.
    /// * An error if it is not possible to authorize the action
    pub async fn change_password(
        &self,
        maybe_user_id: Option<UserId>,
        change_password_form: &ChangePasswordForm,
    ) -> Result<(), ServiceError> {
        let Some(user_id) = maybe_user_id else {
            return Err(ServiceError::UnauthorizedActionForGuests);
        };

        self.authorization_service
            .authorize(ACTION::ChangePassword, maybe_user_id)
            .await?;

        info!("changing user password for user ID: {}", user_id);

        let settings = self.configuration.settings.read().await;

        let user_authentication = self
            .user_authentication_repository
            .get_user_authentication_from_id(&user_id)
            .await?;

        verify_password(change_password_form.current_password.as_bytes(), &user_authentication)?;

        let password_constraints = PasswordConstraints {
            min_password_length: settings.auth.password_constraints.min_password_length,
            max_password_length: settings.auth.password_constraints.max_password_length,
        };

        validate_password_constraints(
            &change_password_form.password,
            &change_password_form.confirm_password,
            &password_constraints,
        )?;

        let password_hash = hash_password(&change_password_form.password)?;

        self.user_authentication_repository
            .change_password(user_id, &password_hash)
            .await?;

        Ok(())
    }
}

pub struct BanService {
    user_profile_repository: Arc<DbUserProfileRepository>,
    banned_user_list: Arc<DbBannedUserList>,
    authorization_service: Arc<authorization::Service>,
}

impl BanService {
    #[must_use]
    pub fn new(
        user_profile_repository: Arc<DbUserProfileRepository>,
        banned_user_list: Arc<DbBannedUserList>,
        authorization_service: Arc<authorization::Service>,
    ) -> Self {
        Self {
            user_profile_repository,
            banned_user_list,
            authorization_service,
        }
    }

    /// Ban a user from the Index.
    ///
    /// # Errors
    ///
    /// This function will return a:
    ///
    /// * `ServiceError::InternalServerError` if unable get user from the request.
    /// * An error if unable to get user profile from supplied username.
    /// * An error if unable to set the ban of the user in the database.
    pub async fn ban_user(&self, username_to_be_banned: &str, maybe_user_id: Option<UserId>) -> Result<(), ServiceError> {
        let Some(user_id) = maybe_user_id else {
            return Err(ServiceError::UnauthorizedActionForGuests);
        };

        self.authorization_service.authorize(ACTION::BanUser, maybe_user_id).await?;

        debug!("user with ID {} banning username: {username_to_be_banned}", user_id);

        let user_profile = self
            .user_profile_repository
            .get_user_profile_from_username(username_to_be_banned)
            .await?;

        self.banned_user_list.add(&user_profile.user_id).await?;

        Ok(())
    }
}

pub struct ListingService {
    configuration: Arc<Configuration>,
    user_profile_repository: Arc<DbUserProfileRepository>,
    authorization_service: Arc<authorization::Service>,
}

impl ListingService {
    #[must_use]
    pub fn new(
        configuration: Arc<Configuration>,
        user_profile_repository: Arc<DbUserProfileRepository>,
        authorization_service: Arc<authorization::Service>,
    ) -> Self {
        Self {
            configuration,
            user_profile_repository,
            authorization_service,
        }
    }

    /// Returns a list of all the user profiles matching the search criteria.
    ///
    /// # Errors
    ///
    /// Returns a `ServiceError::DatabaseError` if the database query fails.
    pub async fn generate_user_profile_listing(
        &self,
        request: &ListingRequest,
        maybe_user_id: Option<UserId>,
    ) -> Result<UserProfilesResponse, ServiceError> {
        self.authorization_service
            .authorize(ACTION::GenerateUserProfilesListing, maybe_user_id)
            .await?;

        let user_profile_listing_specification = self.listing_specification_from_user_request(request).await;

        let user_profiles_response = self
            .user_profile_repository
            .generate_listing(&user_profile_listing_specification)
            .await?;

        Ok(user_profiles_response)
    }

    /// It converts the user listing request into an internal listing
    /// specification.
    async fn listing_specification_from_user_request(&self, request: &ListingRequest) -> ListingSpecification {
        let settings = self.configuration.settings.read().await;
        let default_user_profile_page_size = settings.api.default_user_profile_page_size;
        let max_user_profile_page_size = settings.api.max_user_profile_page_size;
        drop(settings);

        let page = request.page.unwrap_or(0);
        let page_size = request.page_size.unwrap_or(default_user_profile_page_size);

        // Guard that page size does not exceed the maximum
        let page_size = if page_size > max_user_profile_page_size {
            max_user_profile_page_size
        } else {
            page_size
        };

        let offset = u64::from(page * u32::from(page_size));

        ListingSpecification { offset, page_size }
    }
}

pub struct AdminActionsService {
    authorization_service: Arc<authorization::Service>,
    user_authentication_repository: Arc<DbUserAuthenticationRepository>,
}

impl AdminActionsService {
    /// Resets the password of the selected user.
    ///
    /// # Errors
    ///
    /// This function will return a:
    ///
    /// * `ServiceError::InvalidPassword` if the current password supplied is invalid.
    /// * `ServiceError::PasswordsDontMatch` if the supplied passwords do not match.
    /// * `ServiceError::PasswordTooShort` if the supplied password is too short.
    /// * `ServiceError::PasswordTooLong` if the supplied password is too long.
    /// * An error if unable to successfully hash the password.
    /// * An error if unable to change the password in the database.
    /// * An error if it is not possible to authorize the action
    pub async fn reset_user_password(&self, maybe_user_id: Option<UserId>, user_info: UserProfile) -> Result<(), ServiceError> {
        self.authorization_service
            .authorize(ACTION::ResetUserPassword, maybe_user_id)
            .await?;

        info!("Resetting user password for user ID: {}", user_info.username);

        let new_password = generate_random_password();

        let password_hash = hash_password(&new_password)?;

        self.user_authentication_repository
            .change_password(user_info.user_id, &password_hash)
            .await?;

        Ok(())
    }
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait Repository: Sync + Send {
    async fn get_compact(&self, user_id: &UserId) -> Result<UserCompact, ServiceError>;
    async fn grant_admin_role(&self, user_id: &UserId) -> Result<(), Error>;
    async fn delete(&self, user_id: &UserId) -> Result<(), Error>;
    async fn add(&self, username: &str, email: &str, password_hash: &str) -> Result<UserId, Error>;
}

pub struct DbUserRepository {
    database: Arc<Box<dyn Database>>,
}

impl DbUserRepository {
    #[must_use]
    pub fn new(database: Arc<Box<dyn Database>>) -> Self {
        Self { database }
    }
}

#[async_trait]
impl Repository for DbUserRepository {
    /// It returns the compact user.
    ///
    /// # Errors
    ///
    /// It returns an error if there is a database error.
    async fn get_compact(&self, user_id: &UserId) -> Result<UserCompact, ServiceError> {
        // todo: persistence layer should have its own errors instead of
        // returning a `ServiceError`.
        self.database
            .get_user_compact_from_id(*user_id)
            .await
            .map_err(|_| ServiceError::UserNotFound)
    }

    /// It grants the admin role to the user.
    ///
    /// # Errors
    ///
    /// It returns an error if there is a database error.
    async fn grant_admin_role(&self, user_id: &UserId) -> Result<(), Error> {
        self.database.grant_admin_role(*user_id).await
    }

    /// It deletes the user.
    ///
    /// # Errors
    ///
    /// It returns an error if there is a database error.
    async fn delete(&self, user_id: &UserId) -> Result<(), Error> {
        self.database.delete_user(*user_id).await
    }

    /// It adds a new user.
    ///
    /// # Errors
    ///
    /// It returns an error if there is a database error.
    async fn add(&self, username: &str, email: &str, password_hash: &str) -> Result<UserId, Error> {
        self.database.insert_user_and_get_id(username, email, password_hash).await
    }
}

pub struct DbUserProfileRepository {
    database: Arc<Box<dyn Database>>,
}

impl DbUserProfileRepository {
    #[must_use]
    pub fn new(database: Arc<Box<dyn Database>>) -> Self {
        Self { database }
    }

    /// It marks the user's email as verified.
    ///
    /// # Errors
    ///
    /// It returns an error if there is a database error.
    pub async fn verify_email(&self, user_id: &UserId) -> Result<(), Error> {
        self.database.verify_email(*user_id).await
    }

    /// It get the user profile from the username.
    ///
    /// # Errors
    ///
    /// It returns an error if there is a database error.
    pub async fn get_user_profile_from_username(&self, username: &str) -> Result<UserProfile, Error> {
        self.database.get_user_profile_from_username(username).await
    }

    /// It gets all the user profiles for all the users.
    ///
    /// # Errors
    ///
    /// It returns an error if there is a database error.
    pub async fn generate_listing(&self, specification: &ListingSpecification) -> Result<UserProfilesResponse, Error> {
        self.database
            .get_user_profiles_paginated(specification.offset, specification.page_size)
            .await
    }
}

pub struct DbBannedUserList {
    database: Arc<Box<dyn Database>>,
}

impl DbBannedUserList {
    #[must_use]
    pub fn new(database: Arc<Box<dyn Database>>) -> Self {
        Self { database }
    }

    /// It add a user to the banned users list.
    ///
    /// # Errors
    ///
    /// It returns an error if there is a database error.
    ///
    /// # Panics
    ///
    /// It panics if the expiration date cannot be parsed. It should never
    /// happen as the date is hardcoded for now.
    pub async fn add(&self, user_id: &UserId) -> Result<(), Error> {
        // todo: add reason and `date_expiry` parameters to request.

        // code-review: add the user ID of the user who banned the user.

        // For the time being, we will not use a reason for banning a user.
        let reason = "no reason".to_string();

        // User will be banned until the year 9999
        let date_expiry = chrono::NaiveDateTime::parse_from_str("9999-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
            .expect("Could not parse date from 9999-01-01 00:00:00.");

        self.database.ban_user(*user_id, &reason, date_expiry).await
    }
}

fn validate_password_constraints(
    password: &str,
    confirm_password: &str,
    password_rules: &PasswordConstraints,
) -> Result<(), ServiceError> {
    if password != confirm_password {
        return Err(ServiceError::PasswordsDontMatch);
    }

    let password_length = password.len();

    if password_length < password_rules.min_password_length {
        return Err(ServiceError::PasswordTooShort);
    }

    if password_length > password_rules.max_password_length {
        return Err(ServiceError::PasswordTooLong);
    }

    Ok(())
}

fn hash_password(password: &str) -> Result<String, ServiceError> {
    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?.to_string();

    Ok(password_hash)
}

//Generates a random password with numbers, letters and special characters with a length of the max length allow for users's passwords
fn generate_random_password() -> String {
    let charset = "2A&,B;C8D!G?HIJ@KL5MN1OPQ#RST]U`VW*XYZ\
                   {ab)c~d$ef=g.h<i_jklmn%op>qr/st6u+vw}xyz\
                   |0-EF3^4[7(:9\
                   ";

    let mut rng = rand::thread_rng();

    let password_constraints = Auth::default().password_constraints;

    let password_length = password_constraints.max_password_length;

    let password: String = (0..password_length)
        .map(|_| charset.chars().choose(&mut rng).unwrap())
        .collect();

    password
}
