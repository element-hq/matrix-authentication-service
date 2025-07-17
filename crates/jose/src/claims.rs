// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::HashMap, convert::Infallible, marker::PhantomData, ops::Deref};

use base64ct::{Base64UrlUnpadded, Encoding};
use mas_iana::jose::JsonWebSignatureAlg;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClaimError {
    #[error("missing claim {0:?}")]
    MissingClaim(&'static str),

    #[error("invalid claim {0:?}")]
    InvalidClaim(&'static str),

    #[error("could not validate claim {claim:?}")]
    ValidationError {
        claim: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

pub trait Validator<T> {
    /// The associated error type returned by this validator.
    type Error;

    /// Validate a claim value
    ///
    /// # Errors
    ///
    /// Returns an error if the value is invalid.
    fn validate(&self, value: &T) -> Result<(), Self::Error>;
}

impl<T> Validator<T> for () {
    type Error = Infallible;

    fn validate(&self, _value: &T) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct Claim<T, V = ()> {
    value: &'static str,
    t: PhantomData<T>,
    v: PhantomData<V>,
}

impl<T, V> Claim<T, V>
where
    V: Validator<T>,
{
    #[must_use]
    pub const fn new(claim: &'static str) -> Self {
        Self {
            value: claim,
            t: PhantomData,
            v: PhantomData,
        }
    }

    /// Insert a claim into the given claims map.
    ///
    /// # Errors
    ///
    /// Returns an error if the value failed to serialize.
    pub fn insert<I>(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
        value: I,
    ) -> Result<(), ClaimError>
    where
        I: Into<T>,
        T: Serialize,
    {
        let value = value.into();
        let value: serde_json::Value =
            serde_json::to_value(&value).map_err(|_| ClaimError::InvalidClaim(self.value))?;
        claims.insert(self.value.to_owned(), value);

        Ok(())
    }

    /// Extract a claim from the given claims map.
    ///
    /// # Errors
    ///
    /// Returns an error if the value failed to deserialize, if its value is
    /// invalid or if the claim is missing.
    pub fn extract_required(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
    ) -> Result<T, ClaimError>
    where
        T: DeserializeOwned,
        V: Default,
        V::Error: std::error::Error + Send + Sync + 'static,
    {
        let validator = V::default();
        self.extract_required_with_options(claims, validator)
    }

    /// Extract a claim from the given claims map, with the given options.
    ///
    /// # Errors
    ///
    /// Returns an error if the value failed to deserialize, if its value is
    /// invalid or if the claim is missing.
    pub fn extract_required_with_options<I>(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
        validator: I,
    ) -> Result<T, ClaimError>
    where
        T: DeserializeOwned,
        I: Into<V>,
        V::Error: std::error::Error + Send + Sync + 'static,
    {
        let validator: V = validator.into();
        let claim = claims
            .remove(self.value)
            .ok_or(ClaimError::MissingClaim(self.value))?;

        let res =
            serde_json::from_value(claim).map_err(|_| ClaimError::InvalidClaim(self.value))?;
        validator
            .validate(&res)
            .map_err(|source| ClaimError::ValidationError {
                claim: self.value,
                source: Box::new(source),
            })?;
        Ok(res)
    }

    /// Extract a claim from the given claims map, if it exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the value failed to deserialize or if its value is
    /// invalid.
    pub fn extract_optional(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
    ) -> Result<Option<T>, ClaimError>
    where
        T: DeserializeOwned,
        V: Default,
        V::Error: std::error::Error + Send + Sync + 'static,
    {
        let validator = V::default();
        self.extract_optional_with_options(claims, validator)
    }

    /// Extract a claim from the given claims map, if it exists, with the given
    /// options.
    ///
    /// # Errors
    ///
    /// Returns an error if the value failed to deserialize or if its value is
    /// invalid.
    pub fn extract_optional_with_options<I>(
        &self,
        claims: &mut HashMap<String, serde_json::Value>,
        validator: I,
    ) -> Result<Option<T>, ClaimError>
    where
        T: DeserializeOwned,
        I: Into<V>,
        V::Error: std::error::Error + Send + Sync + 'static,
    {
        match self.extract_required_with_options(claims, validator) {
            Ok(v) => Ok(Some(v)),
            Err(ClaimError::MissingClaim(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Assert that the claim is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the claim is present.
    pub fn assert_absent(
        &self,
        claims: &HashMap<String, serde_json::Value>,
    ) -> Result<(), ClaimError> {
        if claims.contains_key(self.value) {
            Err(ClaimError::InvalidClaim(self.value))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimeOptions {
    when: chrono::DateTime<chrono::Utc>,
    leeway: chrono::Duration,
}

impl TimeOptions {
    #[must_use]
    pub fn new(when: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            when,
            leeway: chrono::Duration::microseconds(5 * 60 * 1000 * 1000),
        }
    }

    #[must_use]
    pub fn leeway(mut self, leeway: chrono::Duration) -> Self {
        self.leeway = leeway;
        self
    }
}

#[derive(Debug, Clone, Copy, Error)]
#[error("Current time is too far away")]
pub struct TimeTooFarError;

#[derive(Debug, Clone)]
pub struct TimeNotAfter(TimeOptions);

impl Validator<Timestamp> for TimeNotAfter {
    type Error = TimeTooFarError;
    fn validate(&self, value: &Timestamp) -> Result<(), Self::Error> {
        if self.0.when <= value.0 + self.0.leeway {
            Ok(())
        } else {
            Err(TimeTooFarError)
        }
    }
}

impl From<TimeOptions> for TimeNotAfter {
    fn from(opt: TimeOptions) -> Self {
        Self(opt)
    }
}

impl From<&TimeOptions> for TimeNotAfter {
    fn from(opt: &TimeOptions) -> Self {
        opt.clone().into()
    }
}

#[derive(Debug, Clone)]
pub struct TimeNotBefore(TimeOptions);

impl Validator<Timestamp> for TimeNotBefore {
    type Error = TimeTooFarError;

    fn validate(&self, value: &Timestamp) -> Result<(), Self::Error> {
        if self.0.when >= value.0 - self.0.leeway {
            Ok(())
        } else {
            Err(TimeTooFarError)
        }
    }
}

impl From<TimeOptions> for TimeNotBefore {
    fn from(opt: TimeOptions) -> Self {
        Self(opt)
    }
}

impl From<&TimeOptions> for TimeNotBefore {
    fn from(opt: &TimeOptions) -> Self {
        opt.clone().into()
    }
}

/// Hash the given token with the given algorithm for an ID Token claim.
///
/// According to the [OpenID Connect Core 1.0 specification].
///
/// # Errors
///
/// Returns an error if the algorithm is not supported.
///
/// [OpenID Connect Core 1.0 specification]: https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
pub fn hash_token(alg: &JsonWebSignatureAlg, token: &str) -> Result<String, TokenHashError> {
    let bits = match alg {
        JsonWebSignatureAlg::Hs256
        | JsonWebSignatureAlg::Rs256
        | JsonWebSignatureAlg::Es256
        | JsonWebSignatureAlg::Ps256
        | JsonWebSignatureAlg::Es256K => {
            let mut hasher = Sha256::new();
            hasher.update(token);
            let hash: [u8; 32] = hasher.finalize().into();
            // Left-most half
            hash[..16].to_owned()
        }
        JsonWebSignatureAlg::Hs384
        | JsonWebSignatureAlg::Rs384
        | JsonWebSignatureAlg::Es384
        | JsonWebSignatureAlg::Ps384 => {
            let mut hasher = Sha384::new();
            hasher.update(token);
            let hash: [u8; 48] = hasher.finalize().into();
            // Left-most half
            hash[..24].to_owned()
        }
        JsonWebSignatureAlg::Hs512
        | JsonWebSignatureAlg::Rs512
        | JsonWebSignatureAlg::Es512
        | JsonWebSignatureAlg::Ps512 => {
            let mut hasher = Sha512::new();
            hasher.update(token);
            let hash: [u8; 64] = hasher.finalize().into();
            // Left-most half
            hash[..32].to_owned()
        }
        _ => return Err(TokenHashError::UnsupportedAlgorithm),
    };

    Ok(Base64UrlUnpadded::encode_string(&bits))
}

#[derive(Debug, Clone, Copy, Error)]
pub enum TokenHashError {
    #[error("Hashes don't match")]
    HashMismatch,

    #[error("Unsupported algorithm for hashing")]
    UnsupportedAlgorithm,
}

#[derive(Debug, Clone)]
pub struct TokenHash<'a> {
    alg: &'a JsonWebSignatureAlg,
    token: &'a str,
}

impl<'a> TokenHash<'a> {
    /// Creates a new `TokenHash` validator for the given algorithm and token.
    #[must_use]
    pub fn new(alg: &'a JsonWebSignatureAlg, token: &'a str) -> Self {
        Self { alg, token }
    }
}

impl Validator<String> for TokenHash<'_> {
    type Error = TokenHashError;
    fn validate(&self, value: &String) -> Result<(), Self::Error> {
        if hash_token(self.alg, self.token)? == *value {
            Ok(())
        } else {
            Err(TokenHashError::HashMismatch)
        }
    }
}

#[derive(Debug, Clone, Copy, Error)]
#[error("Values don't match")]
pub struct EqualityError;

#[derive(Debug, Clone)]
pub struct Equality<'a, T: ?Sized> {
    value: &'a T,
}

impl<'a, T: ?Sized> Equality<'a, T> {
    /// Creates a new `Equality` validator for the given value.
    #[must_use]
    pub fn new(value: &'a T) -> Self {
        Self { value }
    }
}

impl<T1, T2> Validator<T1> for Equality<'_, T2>
where
    T2: PartialEq<T1> + ?Sized,
{
    type Error = EqualityError;
    fn validate(&self, value: &T1) -> Result<(), Self::Error> {
        if *self.value == *value {
            Ok(())
        } else {
            Err(EqualityError)
        }
    }
}

impl<'a, T: ?Sized> From<&'a T> for Equality<'a, T> {
    fn from(value: &'a T) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone)]
pub struct Contains<'a, T> {
    value: &'a T,
}

impl<'a, T> Contains<'a, T> {
    /// Creates a new `Contains` validator for the given value.
    #[must_use]
    pub fn new(value: &'a T) -> Self {
        Self { value }
    }
}

#[derive(Debug, Clone, Copy, Error)]
#[error("OneOrMany doesn't contain value")]
pub struct ContainsError;

impl<T> Validator<OneOrMany<T>> for Contains<'_, T>
where
    T: PartialEq,
{
    type Error = ContainsError;
    fn validate(&self, value: &OneOrMany<T>) -> Result<(), Self::Error> {
        if value.contains(self.value) {
            Ok(())
        } else {
            Err(ContainsError)
        }
    }
}

impl<'a, T> From<&'a T> for Contains<'a, T> {
    fn from(value: &'a T) -> Self {
        Self::new(value)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(transparent)]
pub struct Timestamp(#[serde(with = "chrono::serde::ts_seconds")] chrono::DateTime<chrono::Utc>);

impl Deref for Timestamp {
    type Target = chrono::DateTime<chrono::Utc>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<chrono::DateTime<chrono::Utc>> for Timestamp {
    fn from(value: chrono::DateTime<chrono::Utc>) -> Self {
        Timestamp(value)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(
    transparent,
    bound(serialize = "T: Serialize", deserialize = "T: Deserialize<'de>")
)]
pub struct OneOrMany<T>(
    // serde_as seems to not work properly with #[serde(transparent)]
    // We have use plain old #[serde(with = ...)] with serde_with's utilities, which is a bit
    // verbose but works
    #[serde(
        with = "serde_with::As::<serde_with::OneOrMany<serde_with::Same, serde_with::formats::PreferOne>>"
    )]
    Vec<T>,
);

impl<T> Deref for OneOrMany<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<Vec<T>> for OneOrMany<T> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}

impl<T> From<T> for OneOrMany<T> {
    fn from(value: T) -> Self {
        Self(vec![value])
    }
}

/// Claims defined in RFC7519 sec. 4.1
/// <https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1>
mod rfc7519 {
    use super::{Claim, Contains, Equality, OneOrMany, TimeNotAfter, TimeNotBefore, Timestamp};

    pub const ISS: Claim<String, Equality<str>> = Claim::new("iss");
    pub const SUB: Claim<String> = Claim::new("sub");
    pub const AUD: Claim<OneOrMany<String>, Contains<String>> = Claim::new("aud");
    pub const NBF: Claim<Timestamp, TimeNotBefore> = Claim::new("nbf");
    pub const EXP: Claim<Timestamp, TimeNotAfter> = Claim::new("exp");
    pub const IAT: Claim<Timestamp, TimeNotBefore> = Claim::new("iat");
    pub const JTI: Claim<String> = Claim::new("jti");
}

/// Claims defined in OIDC.Core sec. 2 and sec. 5.1
/// <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>
/// <https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims>
mod oidc_core {
    use url::Url;

    use super::{Claim, Equality, Timestamp, TokenHash};

    pub const AUTH_TIME: Claim<Timestamp> = Claim::new("auth_time");
    pub const NONCE: Claim<String, Equality<str>> = Claim::new("nonce");
    pub const AT_HASH: Claim<String, TokenHash> = Claim::new("at_hash");
    pub const C_HASH: Claim<String, TokenHash> = Claim::new("c_hash");

    pub const NAME: Claim<String> = Claim::new("name");
    pub const GIVEN_NAME: Claim<String> = Claim::new("given_name");
    pub const FAMILY_NAME: Claim<String> = Claim::new("family_name");
    pub const MIDDLE_NAME: Claim<String> = Claim::new("middle_name");
    pub const NICKNAME: Claim<String> = Claim::new("nickname");
    pub const PREFERRED_USERNAME: Claim<String> = Claim::new("preferred_username");
    pub const PROFILE: Claim<Url> = Claim::new("profile");
    pub const PICTURE: Claim<Url> = Claim::new("picture");
    pub const WEBSITE: Claim<Url> = Claim::new("website");
    // TODO: email type?
    pub const EMAIL: Claim<String> = Claim::new("email");
    pub const EMAIL_VERIFIED: Claim<bool> = Claim::new("email_verified");
    pub const GENDER: Claim<String> = Claim::new("gender");
    // TODO: date type
    pub const BIRTHDATE: Claim<String> = Claim::new("birthdate");
    // TODO: timezone type
    pub const ZONEINFO: Claim<String> = Claim::new("zoneinfo");
    // TODO: locale type
    pub const LOCALE: Claim<String> = Claim::new("locale");
    // TODO: phone number type
    pub const PHONE_NUMBER: Claim<String> = Claim::new("phone_number");
    pub const PHONE_NUMBER_VERIFIED: Claim<bool> = Claim::new("phone_number_verified");
    // TODO: pub const ADDRESS: Claim<Timestamp> = Claim::new("address");
    pub const UPDATED_AT: Claim<Timestamp> = Claim::new("updated_at");
}

/// Claims defined in OpenID.FrontChannel
/// <https://openid.net/specs/openid-connect-frontchannel-1_0.html#ClaimsContents>
mod oidc_frontchannel {
    use super::Claim;

    pub const SID: Claim<String> = Claim::new("sid");
}

pub use self::{oidc_core::*, oidc_frontchannel::*, rfc7519::*};

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn timestamp_serde() {
        let datetime = Timestamp(
            chrono::Utc
                .with_ymd_and_hms(2018, 1, 18, 1, 30, 22)
                .unwrap(),
        );
        let timestamp = serde_json::Value::Number(1_516_239_022.into());

        assert_eq!(datetime, serde_json::from_value(timestamp.clone()).unwrap());
        assert_eq!(timestamp, serde_json::to_value(&datetime).unwrap());
    }

    #[test]
    fn one_or_many_serde() {
        let one = OneOrMany(vec!["one".to_owned()]);
        let many = OneOrMany(vec!["one".to_owned(), "two".to_owned()]);

        assert_eq!(
            one,
            serde_json::from_value(serde_json::json!("one")).unwrap()
        );
        assert_eq!(
            one,
            serde_json::from_value(serde_json::json!(["one"])).unwrap()
        );
        assert_eq!(
            many,
            serde_json::from_value(serde_json::json!(["one", "two"])).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&one).unwrap(),
            serde_json::json!("one")
        );
        assert_eq!(
            serde_json::to_value(&many).unwrap(),
            serde_json::json!(["one", "two"])
        );
    }

    #[test]
    fn extract_claims() {
        let now = chrono::Utc
            .with_ymd_and_hms(2018, 1, 18, 1, 30, 22)
            .unwrap();
        let expiration = now + chrono::Duration::microseconds(5 * 60 * 1000 * 1000);
        let time_options = TimeOptions::new(now).leeway(chrono::Duration::zero());

        let claims = serde_json::json!({
            "iss": "https://foo.com",
            "sub": "johndoe",
            "aud": ["abcd-efgh"],
            "iat": 1_516_239_022,
            "nbf": 1_516_239_022,
            "exp": 1_516_239_322,
            "jti": "1122-3344-5566-7788",
        });
        let mut claims = serde_json::from_value(claims).unwrap();

        let iss = ISS
            .extract_required_with_options(&mut claims, "https://foo.com")
            .unwrap();
        let sub = SUB.extract_optional(&mut claims).unwrap();
        let aud = AUD
            .extract_optional_with_options(&mut claims, &"abcd-efgh".to_owned())
            .unwrap();
        let nbf = NBF
            .extract_optional_with_options(&mut claims, &time_options)
            .unwrap();
        let exp = EXP
            .extract_optional_with_options(&mut claims, &time_options)
            .unwrap();
        let iat = IAT
            .extract_optional_with_options(&mut claims, &time_options)
            .unwrap();
        let jti = JTI.extract_optional(&mut claims).unwrap();

        assert_eq!(iss, "https://foo.com".to_owned());
        assert_eq!(sub, Some("johndoe".to_owned()));
        assert_eq!(aud.as_deref(), Some(&vec!["abcd-efgh".to_owned()]));
        assert_eq!(iat.as_deref(), Some(&now));
        assert_eq!(nbf.as_deref(), Some(&now));
        assert_eq!(exp.as_deref(), Some(&expiration));
        assert_eq!(jti, Some("1122-3344-5566-7788".to_owned()));

        assert!(claims.is_empty());
    }

    #[test]
    fn time_validation() {
        let now = chrono::Utc
            .with_ymd_and_hms(2018, 1, 18, 1, 30, 22)
            .unwrap();

        let claims = serde_json::json!({
            "iat": 1_516_239_022,
            "nbf": 1_516_239_022,
            "exp": 1_516_239_322,
        });
        let claims: HashMap<String, serde_json::Value> = serde_json::from_value(claims).unwrap();

        // Everything should be fine at this point, the claims iat & nbf == now
        {
            let mut claims = claims.clone();

            // so no leeway should be fine as well here
            let time_options = TimeOptions::new(now).leeway(chrono::Duration::zero());
            assert!(
                IAT.extract_required_with_options(&mut claims, &time_options)
                    .is_ok()
            );
            assert!(
                NBF.extract_required_with_options(&mut claims, &time_options)
                    .is_ok()
            );
            assert!(
                EXP.extract_required_with_options(&mut claims, &time_options)
                    .is_ok()
            );
        }

        // Let's go back in time a bit
        let now = now - chrono::Duration::microseconds(60 * 1000 * 1000);

        {
            // There is now a time variance between the two parties...
            let mut claims = claims.clone();

            // but no time variance is allowed. "iat" and "nbf" validation will fail
            let time_options = TimeOptions::new(now).leeway(chrono::Duration::zero());
            assert!(matches!(
                IAT.extract_required_with_options(&mut claims, &time_options),
                Err(ClaimError::ValidationError { claim: "iat", .. }),
            ));
            assert!(matches!(
                NBF.extract_required_with_options(&mut claims, &time_options),
                Err(ClaimError::ValidationError { claim: "nbf", .. }),
            ));
            assert!(
                EXP.extract_required_with_options(&mut claims, &time_options)
                    .is_ok()
            );
        }

        {
            // This time, there is a two minute leeway, they all should be fine
            let mut claims = claims.clone();

            // but no time variance is allowed. "iat" and "nbf" validation will fail
            let time_options =
                TimeOptions::new(now).leeway(chrono::Duration::microseconds(2 * 60 * 1000 * 1000));
            assert!(
                IAT.extract_required_with_options(&mut claims, &time_options)
                    .is_ok()
            );
            assert!(
                NBF.extract_required_with_options(&mut claims, &time_options)
                    .is_ok()
            );
            assert!(
                EXP.extract_required_with_options(&mut claims, &time_options)
                    .is_ok()
            );
        }

        // Let's wait some time so it expires
        let now = now + chrono::Duration::microseconds((1 + 6) * 60 * 1000 * 1000);

        {
            // At this point, the claims expired one minute ago
            let mut claims = claims.clone();

            // but no time variance is allowed. "exp" validation will fail
            let time_options = TimeOptions::new(now).leeway(chrono::Duration::zero());
            assert!(
                IAT.extract_required_with_options(&mut claims, &time_options)
                    .is_ok()
            );
            assert!(
                NBF.extract_required_with_options(&mut claims, &time_options)
                    .is_ok()
            );
            assert!(matches!(
                EXP.extract_required_with_options(&mut claims, &time_options),
                Err(ClaimError::ValidationError { claim: "exp", .. }),
            ));
        }

        {
            let mut claims = claims;

            // Same, but with a 2 minutes leeway should be fine then
            let time_options =
                TimeOptions::new(now).leeway(chrono::Duration::try_minutes(2).unwrap());
            assert!(
                IAT.extract_required_with_options(&mut claims, &time_options)
                    .is_ok()
            );
            assert!(
                NBF.extract_required_with_options(&mut claims, &time_options)
                    .is_ok()
            );
            assert!(
                EXP.extract_required_with_options(&mut claims, &time_options)
                    .is_ok()
            );
        }
    }

    #[test]
    fn invalid_claims() {
        let now = chrono::Utc
            .with_ymd_and_hms(2018, 1, 18, 1, 30, 22)
            .unwrap();
        let time_options = TimeOptions::new(now).leeway(chrono::Duration::zero());

        let claims = serde_json::json!({
            "iss": 123,
            "sub": 456,
            "aud": 789,
            "iat": "123",
            "nbf": "456",
            "exp": "789",
            "jti": 123,
        });
        let mut claims = serde_json::from_value(claims).unwrap();

        assert!(matches!(
            ISS.extract_required_with_options(&mut claims, "https://foo.com"),
            Err(ClaimError::InvalidClaim("iss"))
        ));
        assert!(matches!(
            SUB.extract_required(&mut claims),
            Err(ClaimError::InvalidClaim("sub"))
        ));
        assert!(matches!(
            AUD.extract_required_with_options(&mut claims, &"abcd-efgh".to_owned()),
            Err(ClaimError::InvalidClaim("aud"))
        ));
        assert!(matches!(
            NBF.extract_required_with_options(&mut claims, &time_options),
            Err(ClaimError::InvalidClaim("nbf"))
        ));
        assert!(matches!(
            EXP.extract_required_with_options(&mut claims, &time_options),
            Err(ClaimError::InvalidClaim("exp"))
        ));
        assert!(matches!(
            IAT.extract_required_with_options(&mut claims, &time_options),
            Err(ClaimError::InvalidClaim("iat"))
        ));
        assert!(matches!(
            JTI.extract_required(&mut claims),
            Err(ClaimError::InvalidClaim("jti"))
        ));
    }

    #[test]
    fn missing_claims() {
        // Empty claim set
        let mut claims = HashMap::new();

        assert!(matches!(
            ISS.extract_required_with_options(&mut claims, "https://foo.com"),
            Err(ClaimError::MissingClaim("iss"))
        ));
        assert!(matches!(
            SUB.extract_required(&mut claims),
            Err(ClaimError::MissingClaim("sub"))
        ));
        assert!(matches!(
            AUD.extract_required_with_options(&mut claims, &"abcd-efgh".to_owned()),
            Err(ClaimError::MissingClaim("aud"))
        ));

        assert!(matches!(
            ISS.extract_optional_with_options(&mut claims, "https://foo.com"),
            Ok(None)
        ));
        assert!(matches!(SUB.extract_optional(&mut claims), Ok(None)));
        assert!(matches!(
            AUD.extract_optional_with_options(&mut claims, &"abcd-efgh".to_owned()),
            Ok(None)
        ));
    }

    #[test]
    fn string_eq_validation() {
        let claims = serde_json::json!({
            "iss": "https://foo.com",
        });
        let mut claims: HashMap<String, serde_json::Value> =
            serde_json::from_value(claims).unwrap();

        ISS.extract_required_with_options(&mut claims.clone(), "https://foo.com")
            .unwrap();

        assert!(matches!(
            ISS.extract_required_with_options(&mut claims, "https://bar.com"),
            Err(ClaimError::ValidationError { claim: "iss", .. }),
        ));
    }

    #[test]
    fn contains_validation() {
        let claims = serde_json::json!({
            "aud": "abcd-efgh",
        });
        let mut claims: HashMap<String, serde_json::Value> =
            serde_json::from_value(claims).unwrap();

        AUD.extract_required_with_options(&mut claims.clone(), &"abcd-efgh".to_owned())
            .unwrap();

        assert!(matches!(
            AUD.extract_required_with_options(&mut claims, &"wxyz".to_owned()),
            Err(ClaimError::ValidationError { claim: "aud", .. }),
        ));
    }
}
