// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Ref: <https://www.rfc-editor.org/rfc/rfc7517.html>

use mas_iana::jose::{
    JsonWebKeyEcEllipticCurve, JsonWebKeyOperation, JsonWebKeyType, JsonWebKeyUse,
    JsonWebSignatureAlg,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use crate::{
    base64::{Base64, Base64UrlNoPad},
    constraints::{Constrainable, Constraint, ConstraintSet},
};

pub(crate) mod private_parameters;
pub(crate) mod public_parameters;

use self::private_parameters::SymetricKeyError;
pub use self::{
    private_parameters::JsonWebKeyPrivateParameters, public_parameters::JsonWebKeyPublicParameters,
};

pub trait ParametersInfo {
    fn kty(&self) -> JsonWebKeyType;
    fn possible_algs(&self) -> &[JsonWebSignatureAlg];
}

/// An utilitary trait to figure out the [`JsonWebKeyEcEllipticCurve`] value for
/// elliptic curves
trait JwkEcCurve {
    const CRV: JsonWebKeyEcEllipticCurve;
}

impl JwkEcCurve for p256::NistP256 {
    const CRV: JsonWebKeyEcEllipticCurve = JsonWebKeyEcEllipticCurve::P256;
}

impl JwkEcCurve for p384::NistP384 {
    const CRV: JsonWebKeyEcEllipticCurve = JsonWebKeyEcEllipticCurve::P384;
}

impl JwkEcCurve for k256::Secp256k1 {
    const CRV: JsonWebKeyEcEllipticCurve = JsonWebKeyEcEllipticCurve::Secp256K1;
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JsonWebKey<P> {
    #[serde(flatten)]
    parameters: P,

    #[serde(default)]
    r#use: Option<JsonWebKeyUse>,

    #[serde(default)]
    key_ops: Option<Vec<JsonWebKeyOperation>>,

    #[serde(default)]
    alg: Option<JsonWebSignatureAlg>,

    #[serde(default)]
    kid: Option<String>,

    #[schemars(with = "Option<String>")]
    #[serde(default)]
    x5u: Option<Url>,

    #[schemars(with = "Vec<String>")]
    #[serde(default)]
    x5c: Option<Vec<Base64>>,

    #[schemars(with = "Option<String>")]
    #[serde(default)]
    x5t: Option<Base64UrlNoPad>,

    #[schemars(with = "Option<String>")]
    #[serde(default, rename = "x5t#S256")]
    x5t_s256: Option<Base64UrlNoPad>,
}

pub type PublicJsonWebKey = JsonWebKey<self::public_parameters::JsonWebKeyPublicParameters>;
pub type PrivateJsonWebKey = JsonWebKey<self::private_parameters::JsonWebKeyPrivateParameters>;

impl TryFrom<PrivateJsonWebKey> for PublicJsonWebKey {
    type Error = SymetricKeyError;

    fn try_from(value: PrivateJsonWebKey) -> Result<Self, Self::Error> {
        value.try_map(JsonWebKeyPublicParameters::try_from)
    }
}

impl<P> JsonWebKey<P> {
    /// Create a new [`JsonWebKey`] with the given parameters.
    #[must_use]
    pub const fn new(parameters: P) -> Self {
        Self {
            parameters,
            r#use: None,
            key_ops: None,
            alg: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
        }
    }

    /// Map the parameters of this [`JsonWebKey`] to a new type, with a fallible
    /// mapper, consuming the original key.
    ///
    /// # Errors
    ///
    /// Returns an error if the mapper returns an error.
    pub fn try_map<M, O, E>(self, mapper: M) -> Result<JsonWebKey<O>, E>
    where
        M: FnOnce(P) -> Result<O, E>,
    {
        Ok(JsonWebKey {
            parameters: mapper(self.parameters)?,
            r#use: self.r#use,
            key_ops: self.key_ops,
            alg: self.alg,
            kid: self.kid,
            x5u: self.x5u,
            x5c: self.x5c,
            x5t: self.x5t,
            x5t_s256: self.x5t_s256,
        })
    }

    /// Map the parameters of this [`JsonWebKey`] to a new type, consuming the
    /// original key.
    pub fn map<M, O>(self, mapper: M) -> JsonWebKey<O>
    where
        M: FnOnce(P) -> O,
    {
        JsonWebKey {
            parameters: mapper(self.parameters),
            r#use: self.r#use,
            key_ops: self.key_ops,
            alg: self.alg,
            kid: self.kid,
            x5u: self.x5u,
            x5c: self.x5c,
            x5t: self.x5t,
            x5t_s256: self.x5t_s256,
        }
    }

    /// Map the parameters of this [`JsonWebKey`] to a new type, with a fallible
    /// mapper, cloning the other fields.
    ///
    /// # Errors
    ///
    /// Returns an error if the mapper returns an error.
    pub fn try_cloned_map<M, O, E>(&self, mapper: M) -> Result<JsonWebKey<O>, E>
    where
        M: FnOnce(&P) -> Result<O, E>,
    {
        Ok(JsonWebKey {
            parameters: mapper(&self.parameters)?,
            r#use: self.r#use.clone(),
            key_ops: self.key_ops.clone(),
            alg: self.alg.clone(),
            kid: self.kid.clone(),
            x5u: self.x5u.clone(),
            x5c: self.x5c.clone(),
            x5t: self.x5t.clone(),
            x5t_s256: self.x5t_s256.clone(),
        })
    }

    /// Map the parameters of this [`JsonWebKey`] to a new type, cloning the
    /// other fields.
    pub fn cloned_map<M, O>(&self, mapper: M) -> JsonWebKey<O>
    where
        M: FnOnce(&P) -> O,
    {
        JsonWebKey {
            parameters: mapper(&self.parameters),
            r#use: self.r#use.clone(),
            key_ops: self.key_ops.clone(),
            alg: self.alg.clone(),
            kid: self.kid.clone(),
            x5u: self.x5u.clone(),
            x5c: self.x5c.clone(),
            x5t: self.x5t.clone(),
            x5t_s256: self.x5t_s256.clone(),
        }
    }

    /// Set the `use` field of this [`JsonWebKey`].
    #[must_use]
    pub fn with_use(mut self, value: JsonWebKeyUse) -> Self {
        self.r#use = Some(value);
        self
    }

    /// Set the `key_ops` field of this [`JsonWebKey`].
    #[must_use]
    pub fn with_key_ops(mut self, key_ops: Vec<JsonWebKeyOperation>) -> Self {
        self.key_ops = Some(key_ops);
        self
    }

    /// Set the `alg` field of this [`JsonWebKey`].
    #[must_use]
    pub fn with_alg(mut self, alg: JsonWebSignatureAlg) -> Self {
        self.alg = Some(alg);
        self
    }

    /// Set the `kid` field of this [`JsonWebKey`].
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Get the `kid` field of this [`JsonWebKey`], if set.
    #[must_use]
    pub const fn alg(&self) -> Option<&JsonWebSignatureAlg> {
        self.alg.as_ref()
    }

    /// Get the inner parameters of this [`JsonWebKey`].
    #[must_use]
    pub const fn params(&self) -> &P {
        &self.parameters
    }
}

impl<P> Constrainable for JsonWebKey<P>
where
    P: ParametersInfo,
{
    fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    fn kty(&self) -> JsonWebKeyType {
        self.parameters.kty()
    }

    fn algs(&self) -> &[JsonWebSignatureAlg] {
        self.parameters.possible_algs()
    }

    fn alg(&self) -> Option<&JsonWebSignatureAlg> {
        self.alg.as_ref()
    }

    fn use_(&self) -> Option<&JsonWebKeyUse> {
        self.r#use.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JsonWebKeySet<P> {
    keys: Vec<JsonWebKey<P>>,
}

impl<P> Default for JsonWebKeySet<P> {
    fn default() -> Self {
        Self {
            keys: Vec::default(),
        }
    }
}

pub type PublicJsonWebKeySet = JsonWebKeySet<self::public_parameters::JsonWebKeyPublicParameters>;
pub type PrivateJsonWebKeySet =
    JsonWebKeySet<self::private_parameters::JsonWebKeyPrivateParameters>;

impl From<PrivateJsonWebKeySet> for PublicJsonWebKeySet {
    fn from(value: PrivateJsonWebKeySet) -> Self {
        let keys = value
            .keys
            .into_iter()
            .filter_map(|key: PrivateJsonWebKey| key.try_into().ok())
            .collect();
        Self { keys }
    }
}

impl<P> std::ops::Deref for JsonWebKeySet<P> {
    type Target = Vec<JsonWebKey<P>>;

    fn deref(&self) -> &Self::Target {
        &self.keys
    }
}

impl<P> JsonWebKeySet<P> {
    #[must_use]
    pub fn new(keys: Vec<JsonWebKey<P>>) -> Self {
        Self { keys }
    }

    /// Find the best key given the constraints
    #[must_use]
    pub fn find_key(&self, constraints: &ConstraintSet) -> Option<&JsonWebKey<P>>
    where
        P: ParametersInfo,
    {
        constraints.filter(&self.keys).pop()
    }

    /// Find the list of keys which match the given constraints
    #[must_use]
    pub fn find_keys(&self, constraints: &ConstraintSet) -> Vec<&JsonWebKey<P>>
    where
        P: ParametersInfo,
    {
        constraints.filter(&self.keys)
    }

    /// Find a key for the given algorithm. Returns `None` if no suitable key
    /// was found.
    #[must_use]
    pub fn signing_key_for_algorithm(&self, alg: &JsonWebSignatureAlg) -> Option<&JsonWebKey<P>>
    where
        P: ParametersInfo,
    {
        let constraints = ConstraintSet::new([
            Constraint::alg(alg),
            Constraint::use_(&mas_iana::jose::JsonWebKeyUse::Sig),
        ]);
        self.find_key(&constraints)
    }

    /// Get a list of available signing algorithms for this [`JsonWebKeySet`]
    #[must_use]
    pub fn available_signing_algorithms(&self) -> Vec<JsonWebSignatureAlg>
    where
        P: ParametersInfo,
    {
        let mut algs: Vec<_> = self
            .keys
            .iter()
            .flat_map(|key| key.params().possible_algs())
            .cloned()
            .collect();
        algs.sort();
        algs.dedup();
        algs
    }
}

impl<P> FromIterator<JsonWebKey<P>> for JsonWebKeySet<P> {
    fn from_iter<T: IntoIterator<Item = JsonWebKey<P>>>(iter: T) -> Self {
        let keys = iter.into_iter().collect();
        Self { keys }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::ConstraintSet;

    #[test]
    fn load_google_keys() {
        let jwks = serde_json::json!({
          "keys": [
            {
              "alg": "RS256",
              "kty": "RSA",
              "n": "tCwhHOxX_ylh5kVwfVqW7QIBTIsPjkjCjVCppDrynuF_3msEdtEaG64eJUz84ODFNMCC0BQ57G7wrKQVWkdSDxWUEqGk2BixBiHJRWZdofz1WOBTdPVicvHW5Zl_aIt7uXWMdOp_SODw-O2y2f05EqbFWFnR2-1y9K8KbiOp82CD72ny1Jbb_3PxTs2Z0F4ECAtTzpDteaJtjeeueRjr7040JAjQ-5fpL5D1g8x14LJyVIo-FL_y94NPFbMp7UCi69CIfVHXFO8WYFz949og-47mWRrID5lS4zpx-QLuvNhUb_lSqmylUdQB3HpRdOcYdj3xwy4MHJuu7tTaf0AmCQ",
              "use": "sig",
              "kid": "d98f49bc6ca4581eae8dfadd494fce10ea23aab0",
              "e": "AQAB"
            },
            {
              "use": "sig",
              "kty": "RSA",
              "kid": "03e84aed4ef4431014e8617567864c4efaaaede9",
              "n": "ma2uRyBeSEOatGuDpCiV9oIxlDWix_KypDYuhQfEzqi_BiF4fV266OWfyjcABbam59aJMNvOnKW3u_eZM-PhMCBij5MZ-vcBJ4GfxDJeKSn-GP_dJ09rpDcILh8HaWAnPmMoi4DC0nrfE241wPISvZaaZnGHkOrfN_EnA5DligLgVUbrA5rJhQ1aSEQO_gf1raEOW3DZ_ACU3qhtgO0ZBG3a5h7BPiRs2sXqb2UCmBBgwyvYLDebnpE7AotF6_xBIlR-Cykdap3GHVMXhrIpvU195HF30ZoBU4dMd-AeG6HgRt4Cqy1moGoDgMQfbmQ48Hlunv9_Vi2e2CLvYECcBw",
              "e": "AQAB",
              "alg": "RS256"
            }
          ]
        });

        let jwks: PublicJsonWebKeySet = serde_json::from_value(jwks).unwrap();
        // Both keys are RSA public keys
        for jwk in &jwks.keys {
            let p = jwk.params().rsa().expect("an RSA key");
            rsa::RsaPublicKey::try_from(p).unwrap();
        }

        let constraints = ConstraintSet::default()
            .use_(&JsonWebKeyUse::Sig)
            .kty(&JsonWebKeyType::Rsa)
            .alg(&JsonWebSignatureAlg::Rs256);
        let candidates = constraints.filter(&jwks.keys);
        assert_eq!(candidates.len(), 2);

        let constraints = ConstraintSet::default()
            .use_(&JsonWebKeyUse::Sig)
            .kty(&JsonWebKeyType::Rsa)
            .kid("03e84aed4ef4431014e8617567864c4efaaaede9");
        let candidates = constraints.filter(&jwks.keys);
        assert_eq!(candidates.len(), 1);
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn load_keycloak_keys() {
        let jwks = serde_json::json!({
          "keys": [
            {
              "kid": "SuGUPE9Sr-1Gha2NLse33r5NQu3XoS_I3Qds3bcmfQE",
              "kty": "RSA",
              "alg": "RS256",
              "use": "sig",
              "n": "j21ih2m1RPeTXtIPFas2ZclhW8v2RitLdXJTqOFviWonaSObUWNZUkVvIdDKDyJhU7caGPnz52zXX1Trhbbq1uoCalAuIPw9UgJUJhUhlH7lqaRtYdbOrOzXZ7kVsApe1OdlezgShnyMhW5ChEJXQrCkR_LktBJQ8-6ZBNLHx3ps-pQrpXky_XdYZM_I_f1R8z36gnXagklAMMNKciFRURBMAsPbOgaly-slEDdVcuNtcoccSYdo9kRS5wjQlK6LZ3lniJrLRkUMvN6ZQcMLUWMDpghH5bdbhaaOb28HQWwpRDEBIMIH9Fi9aiKxwHa5YAqW1yetOq_9XXyYiuP9G6hZozSnkkfAOzYFqfr92vIPHddVVUUVLvH8UL4u1o553uVtOExA_pJVRghfO0IPZhJ6rUaZR7krvUMdCYngGznuD_V2-TAL9Nu8YXHIrZSU4WBKIvQC2HDOogSjj5dNDBUuAmOhI2OjuLjiOXpRPlaGcMIIlLALwQ76gFTEhTDlRXar7oLU8wj1KHLkc6d__lwdBkR-2Fr4dAewW4bHVFsPeDSM_vJZpK0XACrNgrrNBax48_hOlK9YfzSopyVCHwewxmC743eNYWEhE9LY-cc3ZGK9tHXgQG2l1tOZ_JK9wo1HsIuu3gdl2SV3ZOs6Ggi812GMfrgijnthC7e4Mv8",
              "e": "AQAB",
              "x5c": [
                "MIIElTCCAn0CBgF95wE6HzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANkZXYwHhcNMjExMjIzMTExNDE3WhcNMzExMjIzMTExNTU3WjAOMQwwCgYDVQQDDANkZXYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCPbWKHabVE95Ne0g8VqzZlyWFby/ZGK0t1clOo4W+JaidpI5tRY1lSRW8h0MoPImFTtxoY+fPnbNdfVOuFturW6gJqUC4g/D1SAlQmFSGUfuWppG1h1s6s7NdnuRWwCl7U52V7OBKGfIyFbkKEQldCsKRH8uS0ElDz7pkE0sfHemz6lCuleTL9d1hkz8j9/VHzPfqCddqCSUAww0pyIVFREEwCw9s6BqXL6yUQN1Vy421yhxxJh2j2RFLnCNCUrotneWeImstGRQy83plBwwtRYwOmCEflt1uFpo5vbwdBbClEMQEgwgf0WL1qIrHAdrlgCpbXJ606r/1dfJiK4/0bqFmjNKeSR8A7NgWp+v3a8g8d11VVRRUu8fxQvi7Wjnne5W04TED+klVGCF87Qg9mEnqtRplHuSu9Qx0JieAbOe4P9Xb5MAv027xhccitlJThYEoi9ALYcM6iBKOPl00MFS4CY6EjY6O4uOI5elE+VoZwwgiUsAvBDvqAVMSFMOVFdqvugtTzCPUocuRzp3/+XB0GRH7YWvh0B7BbhsdUWw94NIz+8lmkrRcAKs2Cus0FrHjz+E6Ur1h/NKinJUIfB7DGYLvjd41hYSET0tj5xzdkYr20deBAbaXW05n8kr3CjUewi67eB2XZJXdk6zoaCLzXYYx+uCKOe2ELt7gy/wIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQB+mzE9ZA/hX/GAM74ZXs+ZEjV+qzUsGNpHkXyzdRc1ic28Go5ujAIMxwwsJ4PUSmw6MjPpCKV3kSXoyc7kUDZ/NQ7gwanP4DN8wDq7GLGqT3QRzMLfVy+el2Vjwd3Q6BhXNAK/jPzv0DFu1GG4WCpc1PcM8p/zWkbKWf9u4nBl7RBsMddn7KLxV+D2Y2eGshZ81YVaJiKF9y+gpgyxBOOsTFITu8SxBpXSwBIP4jTv7NllicxI8G9mk87XX3DdA+NHPKsKj35RbDAXyMid8tMl4R3IQ34F3ADuquHpdAdfTNDSm5lwilyWjV35O+8mKA2n/3LAhfCNgxMU0m9Jm8kI/pu9qTXnIx+HMr8IsAMseGxl+dZ/jJjGGPw1VZhHhU78dN+DZlUSKOVjOSQF+8CGuCxMnOx7+leGafs6G6LtsF/vQvJBTB9DRlM3ag0hQRT2ZEXPWSvcz3ARXqWyaHTzhR4F/+rRX1CyBsCdG3b3iicjGp7EPeaqXEki1K3SNwwv1byeJfqP785auswpojpUYfp/J850VAfA4xuVvxK3xuJrvbpS4DR6JQPY0fs6g8JEDahYa6rSB8H9toLC2r92gerqcGFpEU8uHRHxm9QZjIyFh78LWqpfegz0HMjYqaULgZJxqqZH2sVIu+nPuKC7tIjYWtODR0A13Ar3lH8aZg=="
              ],
              "x5t": "fvgfH2gggONL7t4ZTvOdBpI94kM",
              "x5t#S256": "uwHwO2crQ74jak2bmAeAt_4nrqGDQoElaiVvOlSGOOw"
            },
            {
              "kid": "7pW7bkOM27LQ-KJGHzT1dt3yBmhcj20xj7A-itsuY6U",
              "kty": "RSA",
              "alg": "RS384",
              "use": "sig",
              "n": "lI1actdwWsMY8BpY68x8No7fwokLTTcZ8-qpqF9CDwX40X70ql9JPqTpLAHp7H7byfO-8VqZVKYKdzFCLjaEqs6Vx6YYuu4BsM2RIDI2CmClngUE5RMXnaEj8XP-h8Q4FnGcXL47n2UNr9mbZSp85W0TWOLtMczuqwwJ2jcYkDFtvLY0UirioKzN5Vr29WdDiCm9i4jHvHE7W41LFCOFLOLxGOq9wLVRNRMRcC3YS6WlrfiMFkPQIGxzFH2OiW2iR9x8QHmxqrqdfidmFsosgG5_2tbX3Q5PnHjYTNHh-iY4uIQ6bsBj1Enoj5h5kudwtgHDyn9OAiljTqLMXsoK9KEZrjE8zPnxQtvfXLCby2CI69X5JZ2lQJCch4cn1eIxn-jJ9Z0aE9EML1Bfp6w5sKELXt1aRtu5HQ5IQ__y2sBJd91NdiBxAzCK5kZjhRIRtt57J5ZHTLsBeHvr2L7SwZ_FojrQly7mI5PMGthZoGoVAr-bJcInzICpcsLKWdW-C6jxhXwRtnJOuTizEOr33vnLohMlmJUZiomYnKv8MEFAmihK5GAHTJ-4QIUuUeC13Dl5aRJacxvoKfgR_zw9P6HCUb7Nq7uzN3oqUdmDYYng1OFVo-1liYuCLbH6ep5LTmAstQY3IjkIFKeY-tvSPdpC9y1TwaHqEktXckvRGx0",
              "e": "AQAB",
              "x5c": [
                "MIIElTCCAn0CBgF95wGjLjANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANkZXYwHhcNMjExMjIzMTExNDQzWhcNMzExMjIzMTExNjIzWjAOMQwwCgYDVQQDDANkZXYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCUjVpy13BawxjwGljrzHw2jt/CiQtNNxnz6qmoX0IPBfjRfvSqX0k+pOksAensftvJ877xWplUpgp3MUIuNoSqzpXHphi67gGwzZEgMjYKYKWeBQTlExedoSPxc/6HxDgWcZxcvjufZQ2v2ZtlKnzlbRNY4u0xzO6rDAnaNxiQMW28tjRSKuKgrM3lWvb1Z0OIKb2LiMe8cTtbjUsUI4Us4vEY6r3AtVE1ExFwLdhLpaWt+IwWQ9AgbHMUfY6JbaJH3HxAebGqup1+J2YWyiyAbn/a1tfdDk+ceNhM0eH6Jji4hDpuwGPUSeiPmHmS53C2AcPKf04CKWNOosxeygr0oRmuMTzM+fFC299csJvLYIjr1fklnaVAkJyHhyfV4jGf6Mn1nRoT0QwvUF+nrDmwoQte3VpG27kdDkhD//LawEl33U12IHEDMIrmRmOFEhG23nsnlkdMuwF4e+vYvtLBn8WiOtCXLuYjk8wa2FmgahUCv5slwifMgKlywspZ1b4LqPGFfBG2ck65OLMQ6vfe+cuiEyWYlRmKiZicq/wwQUCaKErkYAdMn7hAhS5R4LXcOXlpElpzG+gp+BH/PD0/ocJRvs2ru7M3eipR2YNhieDU4VWj7WWJi4Itsfp6nktOYCy1BjciOQgUp5j629I92kL3LVPBoeoSS1dyS9EbHQIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCBKgIXOSH8cLgKHq1Q5Zn69YdVpC8W8gp3hfjqa9lpER8MHyZVw0isOzdICrNZdgsatq/uaYBMkc3LwxDRWJVN8AmKabqy6UDlAwHf7IUJJMcu3ODG+2tsy3U1SGIVWIffpOfv3F/gXxU76IXWnHiUzjCMYnWJg0Oy0G2oCDHk/7h82Dmq688UmPW+ycZhktjZ8lXqlopVZhjssTa48xJjtDdwN8OVmPGpV/uVzlDTCuYbyVWTYrEfnKwwVhzmAoIYc4XxDKZQ/z1zqE3HtIGrems7lGpgry55JMIRSYxoD2gg2YscDvuCnfzITwTPjijuyI7ocP6eA13FHriIcfHYEzKENUoEgWeybgs09JyIp3yE7YelL94vY4xJRVeL1jMmP5Wi6pM9cMKgQwkUzq7tmupkh9c6jF+tPStByDvD11ybJi5A/S2Rmer2qhlgnsml4NHkMZgIcWtokxoGmXoMcz6AOx31nRvvBHjC2emVnUmzojTCc5mPY3TRgzlAb+cQE/JIreZMfhfLwk4ny5dq+r4ya02fo7BrDA8oJJAP0gC82KNW5aZVpZSbkeRdogTVWdmiNYxvq95gI4ijLneYwSgWb1PM+CRhlNY7neJEv0VT5fbMd0XQZnxzSzQVymPiBHMEJBUul6UuxjVlJb7cdCtIty0zEWO3/uaEzqQl3w=="
              ],
              "x5t": "Fk9zR2uLwBS6fHJbxM08TjDhUi8",
              "x5t#S256": "ZiBGLQCaqehbgYF5A2dicp7WaL-zE4UTbFYyHKXDU_o"
            },
            {
              "kid": "Jnf5fTyMpeiUyJnc3PHJaM9pR6VjWejv9RVyJgPugFs",
              "kty": "RSA",
              "alg": "RS512",
              "use": "sig",
              "n": "m3Y_aeHLL00X-bBPF3ySQ5ebOQ0dz40IQ4uWwWzL59zxn1AwzqrfrfAkKt_RJvJycfmy4zFeu89bNI86r6PtQVSvLqRYKo9UI4Y5jXs4HyvGvSL-DOXl8b8ybpo-o3bEiTgGOvIw2NGv49xT-_3SJ4Rba6awqVxkj334eZunrfvwYG9bjbAgPqWgMcuLVQNdNpytRHMB8Cjnd0SouL1dVxHlgHpYsZcRbsTsvPO1fRHcQRel44CgQRCZ08BvgETrF_9eATiRKBz18XbhaCZfSqh3a7IA-w9e236w6oD4ATOigeMHYZ0sfqKeoCsSd4rQ9kVc-U_EtL73_BVV7pmM4Xcl8JB8vzi_FMQVotzj5SgawylIxRdWUOGjyVFcUJ_u-DikoneVway0T4fXFJkWUflIoqf5-lHmMupb32q0E_pNL728yOlBfqm3bfJF9SF9w-h2SFMHWdRUzVOrtDRdrJVReGPPWvUHByALLL6B33FEcHDIcw4wqSfEmD6ypYJQxX8Er3_X9QFCgkn_rYUitUx90jOZ0n5vhubYnhiXX3RpeOCh9gF2O3h9Tv-DrynUO6OOgUSsBBbI-tGC5ebT51P0IJRkK3i4TkIYZnv7lj2auGWMC0-o7w24k_fG4U0EAr9N2cenR3Pepl6pjTa2g3y3C5_0LDUrcd67QPKl6ZE",
              "e": "AQAB",
              "x5c": [
                "MIIElTCCAn0CBgF95wHdoDANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANkZXYwHhcNMjExMjIzMTExNDU4WhcNMzExMjIzMTExNjM4WjAOMQwwCgYDVQQDDANkZXYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCbdj9p4csvTRf5sE8XfJJDl5s5DR3PjQhDi5bBbMvn3PGfUDDOqt+t8CQq39Em8nJx+bLjMV67z1s0jzqvo+1BVK8upFgqj1QjhjmNezgfK8a9Iv4M5eXxvzJumj6jdsSJOAY68jDY0a/j3FP7/dInhFtrprCpXGSPffh5m6et+/Bgb1uNsCA+paAxy4tVA102nK1EcwHwKOd3RKi4vV1XEeWAelixlxFuxOy887V9EdxBF6XjgKBBEJnTwG+AROsX/14BOJEoHPXxduFoJl9KqHdrsgD7D17bfrDqgPgBM6KB4wdhnSx+op6gKxJ3itD2RVz5T8S0vvf8FVXumYzhdyXwkHy/OL8UxBWi3OPlKBrDKUjFF1ZQ4aPJUVxQn+74OKSid5XBrLRPh9cUmRZR+Uiip/n6UeYy6lvfarQT+k0vvbzI6UF+qbdt8kX1IX3D6HZIUwdZ1FTNU6u0NF2slVF4Y89a9QcHIAssvoHfcURwcMhzDjCpJ8SYPrKlglDFfwSvf9f1AUKCSf+thSK1TH3SM5nSfm+G5tieGJdfdGl44KH2AXY7eH1O/4OvKdQ7o46BRKwEFsj60YLl5tPnU/QglGQreLhOQhhme/uWPZq4ZYwLT6jvDbiT98bhTQQCv03Zx6dHc96mXqmNNraDfLcLn/QsNStx3rtA8qXpkQIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQAf2H6GjobSvc50L+cXeizzG6rg6Sm3x31PB7AH7XlVI+cytWA0X04IhuX+9H2VdEqujSApY/WM9voneyEm1eC3L6p4StO7icB+H4GYctzY+KV0qlbH3iMQkz+xngOTaEj+c9lSZlG7FSlL7Eybjjlj9mLyNJv4aiW7lQCxTWu7RcFq+w2ogvR7iv4uwbY9SHO/Fs5qbwzNIP65W9abcZvEAZKXQ69jOZ01VhNqiIA2D0OstjLWTfGaO0WxrUxvBVRqB3a86qIIwHjatrqdoGasLLGz8bAU3rY2b/DwZ7VBljUuZ+7PlysSK3w22k6eQe5G+XgxSl4Mzn+6lzCdoXeSVUzvQZrk+JBaDTVN5V5fteHSjLcaGNwIg9qYOHdx7PBYhbHP/hXADSQH90xIMipG168NOGBaxw+ybCaD6Eg+PfsPGnXO0Wnnd0PN/Dz4LggTLBwlbWaIDltj++0Xxlf375MrK1A9mDkhcdAOzZtkBkTD9UeXqL6UD0R0CFHp0B+TQEZuOuKRMKmlA2eo8f8z70vGToYk5TW/lvi8Li44+Y7UGLlLirpOtfBI35TPLK0OGfLh1dfqnuFQACObk+Ia+ON//r203sSQYQf3Qcq7u5KC/S406W+dSJ+c7Cf+8piMVc42PhYemdrkEPgzuTmzTJga2HFQk8BCUwoL1euMdw=="
              ],
              "x5t": "bPku6_PBAoke1DpEcT0ghZYp6Fc",
              "x5t#S256": "kIo7Hxj-A4jrwOBfo87c2kmAZzs87OHSd8tS4s_PGgk"
            },
            {
              "kid": "WerdZfF_9ZgxLyHepk92CsKAEubvCs3rIAAy6wrUZUc",
              "kty": "RSA",
              "alg": "PS256",
              "use": "sig",
              "n": "85fgcXq_tB48BI8oeF9gjeWqL1opGtHoXv4rmwaxwfwzFU2ywJWRIEjwcJ_ypMPdC1im_kz_VCqWZBFyXfpuaEFkcsIAlLLnklI2TPUD3SV5taV_TXA61fm59K59iJDJr9EaQ_j5WJRGRluJpAi_q55U1vBWAHtnweL9RveQ-Ykc_qhpCcGDIek3-tAvJtVCpKQb764tkvmBD3pUPYTdVKHW4TAp4wFcgcj78E-xWELfm0T1nr7kZu-mV9DGYBZhFIWkf0lm4KA6NVDwWe-d1k-20FpT1tNsugK2Zx7SX2N5ytM2bCLH88Fcphvh9Bw_t7GgtZ9PvihJXdJcHR8nqlCsRMsGpeS6tnEl4E8StcTccgOkw1n2FJ-xxLM9eMOcfY--B9eKSaLRjLrhvWfa5-MGpB5JFrB4Rv17SD02Uoz1lwogCXPzTbKkBJhiA-YDinTRyGzyHTNXWsrmOLXrVRXUqdNYG32mpy1m3cSpoz9fOWne2dKKj9eawxFHa-GCzdfX3JBfgVKGGgaL5E_HlkJxx9OHNfQQQ4_OjyzqQGCoPG7jDCn9svb7hOE2epmYywShCgCsL_DZmTm3OdVWMLZ6oi77SIytWSx8QDy5KNCx3YsSLDg7sWv6t58gerWv1gkjhFzhyi3mqsw53WkeUyInrLoDYzEPkjWv3kSKQeM",
              "e": "AQAB",
              "x5c": [
                "MIIElTCCAn0CBgF95wIdDjANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANkZXYwHhcNMjExMjIzMTExNTE1WhcNMzExMjIzMTExNjU1WjAOMQwwCgYDVQQDDANkZXYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDzl+Bxer+0HjwEjyh4X2CN5aovWika0ehe/iubBrHB/DMVTbLAlZEgSPBwn/Kkw90LWKb+TP9UKpZkEXJd+m5oQWRywgCUsueSUjZM9QPdJXm1pX9NcDrV+bn0rn2IkMmv0RpD+PlYlEZGW4mkCL+rnlTW8FYAe2fB4v1G95D5iRz+qGkJwYMh6Tf60C8m1UKkpBvvri2S+YEPelQ9hN1UodbhMCnjAVyByPvwT7FYQt+bRPWevuRm76ZX0MZgFmEUhaR/SWbgoDo1UPBZ753WT7bQWlPW02y6ArZnHtJfY3nK0zZsIsfzwVymG+H0HD+3saC1n0++KEld0lwdHyeqUKxEywal5Lq2cSXgTxK1xNxyA6TDWfYUn7HEsz14w5x9j74H14pJotGMuuG9Z9rn4wakHkkWsHhG/XtIPTZSjPWXCiAJc/NNsqQEmGID5gOKdNHIbPIdM1dayuY4tetVFdSp01gbfaanLWbdxKmjP185ad7Z0oqP15rDEUdr4YLN19fckF+BUoYaBovkT8eWQnHH04c19BBDj86PLOpAYKg8buMMKf2y9vuE4TZ6mZjLBKEKAKwv8NmZObc51VYwtnqiLvtIjK1ZLHxAPLko0LHdixIsODuxa/q3nyB6ta/WCSOEXOHKLeaqzDndaR5TIiesugNjMQ+SNa/eRIpB4wIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQDtW7hL3dWY0Nu87SkAPweBLocyI/S2/XZogBByzqdEWZru+26xQoUacqgYbrmQ6frQfWwlfpuzp7HBheDAHVobjlhl2jUQ7xO5vzTiB1bd/X1cQgOdTHosqiyTXLRBJKr3GQyfjrS3ruWKScGg5Y4jYGbsAoO3cNProddFeLbak0aQXGkhyWib2CzqtIpBA9Zy7EJYIWd5O+tExNIv+mjhSZZ6s3qdWXo/4RkVzBeGx5PApdoI/B7y0vwg4Dlt8qB9JcV9WL4nzI4s8foPMXuXgg+HJllB+NkSnTlQj77oU3pbrBoYgVhEdbfYkQuIdwYOWBQi/hdmV0YjUQQTAjYKBFKWQWCoAVKnfMpbDkdjN8KhOzohZ7KEahvHsnFt/PnS5MlFseZN9e6k4MB96EQ4fem7n/sPx4zqvhZMrPCaUT616hfCTa3DPoHzi2CxebE7GE95veQOtk9jCsXEbqKPvZ83/dfz5ftWu5wGHnhIK9S5sCCgjo2RA8bCLBl6/tBpmE0BwWqQqSZEs4zyXTplko822aJyxJtYprmDK0Ktxm6IEjSpEDCLuirnpQ0+Z8w19Key58Kx+OhNHczJK9wEaygKBQC1vvPV8ZvcHOx4XJgL8QwbPhaR5706YRfXTBceK2aw+oWzoNLJ4X7B2LB9IA84pJZKW+VfmnBz52iiqw=="
              ],
              "x5t": "Xdy9viGu6isFknWeThJbh2_r4Qo",
              "x5t#S256": "-toFY0ysJ3uopRPDNIQBo2VV_XT5YkniW2I-6XK_2oc"
            },
            {
              "kid": "JjGFU4NwBkjaNRmIEw5BpoggXtG8dsl4s7gs29eYvno",
              "kty": "RSA",
              "alg": "PS384",
              "use": "sig",
              "n": "h3RNtfVqZPTQuFYBN54gOgcLX7bK-3qUyXstFso_V09RCHLHbFZV_czEC30lRQ6U5QeZ7iFpu7GbiM1csBk4HqhQ2v0TnjlQxIv9-71VV1JPZHrKsDFZlSr4HlZhkt6myBH16aDBT56U8pKg4oAVkoYS4dpzsR0q30zzrKAMgHRLTYWbCaGGGa1BuEUF9WgUhVnuiMu4ay9Tv0auu1UsdTkXjdR2YcWv2AihvFb4xYUSMBQr0bvUeMF_AAJ0B0VrGWIb51nARO2PNimKviHnFTrlaOyFJsnzwiiijuaOx2HZMQfcObzTz4Hx_YYIexOS83bYYkyGgvgUdu0wqls7ChgaZ_qiQdNnr_RWahIN2iVhjyOJuqsFsXufvHYo0nB1BFm1gnDHgYXdJIrSPql4g9gh1NZD_P0PuniPq3jvPoiQJ2u_9a8RDe9Scb_KzRgrBk0tkaXELDw1Q7ccJx9HUUbTxNkzNtZ6Z4MiKT4n0Bx4joglnL1BXvM5yrlO89brXAmfZgx6OmH7Dractz_Bny6QUHwF5vLMhMuVXsC5dU6UbkSZq82S5SnwnLHAe4JBOC-FTB08wAKgQXat16MIqmrBuKVtdNSshAxMk0wd_jPe-G4A_2RJ6pXSrQOkUFNPrOfV_PQMqI92zCYbIByWEwdfQAkavR2HC0-iDd202NM",
              "e": "AQAB",
              "x5c": [
                "MIIElTCCAn0CBgF95wJajzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANkZXYwHhcNMjExMjIzMTExNTMwWhcNMzExMjIzMTExNzEwWjAOMQwwCgYDVQQDDANkZXYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCHdE219Wpk9NC4VgE3niA6Bwtftsr7epTJey0Wyj9XT1EIcsdsVlX9zMQLfSVFDpTlB5nuIWm7sZuIzVywGTgeqFDa/ROeOVDEi/37vVVXUk9kesqwMVmVKvgeVmGS3qbIEfXpoMFPnpTykqDigBWShhLh2nOxHSrfTPOsoAyAdEtNhZsJoYYZrUG4RQX1aBSFWe6Iy7hrL1O/Rq67VSx1OReN1HZhxa/YCKG8VvjFhRIwFCvRu9R4wX8AAnQHRWsZYhvnWcBE7Y82KYq+IecVOuVo7IUmyfPCKKKO5o7HYdkxB9w5vNPPgfH9hgh7E5LzdthiTIaC+BR27TCqWzsKGBpn+qJB02ev9FZqEg3aJWGPI4m6qwWxe5+8dijScHUEWbWCcMeBhd0kitI+qXiD2CHU1kP8/Q+6eI+reO8+iJAna7/1rxEN71Jxv8rNGCsGTS2RpcQsPDVDtxwnH0dRRtPE2TM21npngyIpPifQHHiOiCWcvUFe8znKuU7z1utcCZ9mDHo6YfsOtpy3P8GfLpBQfAXm8syEy5VewLl1TpRuRJmrzZLlKfCcscB7gkE4L4VMHTzAAqBBdq3XowiqasG4pW101KyEDEyTTB3+M974bgD/ZEnqldKtA6RQU0+s59X89Ayoj3bMJhsgHJYTB19ACRq9HYcLT6IN3bTY0wIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQAoudkN4cTAnT2b7cd/JklLFLBnw+mwSgj0ZYyRByBiC0AXU+LmM+D1Bs0TRqXKICBZ2dxKRr8Z1PdQe8BghWcl84iLXEjHVdw08/xVaQ5GKcGLOfSRG+3Suj6UyZfwcMJtX4GO919fX10mAlk6ySHe6SViSVMup5ePwA0C7Jws9/aXNLIvw82hIX8IVM1kuuu3DICQlr1nsvbu6XVQT5kdhIpApr+IDrBvNFWKPdH+vA8Kxb8wkhk9HIUbAi3WqftHoiI8Qq92BYcB5gjwocAkzmrDDoAulEM24+IJoK87DWEeC0Vu9kOB7i5PKXqUANJ7ebQJJhgXy+xNq1Alh4f95mqolXCxdo1jJi/OFExLDr93Fk5QVRQxi2aSEDkoz/h7stzuUvvTyT75pJAILSL+xv8Gd/bYhL5lfCXcHA9uPDQwM/9gnA1ojIdF1bvgaEo2r1xoY/LAScTB0nzvRh1EVoZYxBHid+79MJWQq0vpJ58pyKcxgKaoD1pUQ2brAlYFNflNiMN18VnCF7vnY8Ol9Po881ee2TWLex0i5cLREo4fvPNg0QgoaQvDqlvJqr1nJll/Mzv2w9s3agQxPwKRkTOTb4jNOV23Uy0SbxBD42EOllLmUN897ra3pdmacHHMatw75Sfcu4WhuMrN13RzVUARMjFN+nNI8i7ay9WJOA=="
              ],
              "x5t": "4ovci1k_HPeLoL2PhUrmoDlLQhU",
              "x5t#S256": "PJsKbXoQ7tZoR7aRDli60V65BPtO-Q7QSpk5P5hDcLY"
            },
            {
              "kid": "zesnP0SwjgVGBU5RPhqccF0W4BbMkbwtZpjAeTAgwz8",
              "kty": "RSA",
              "alg": "PS512",
              "use": "sig",
              "n": "x4NHNpmzOgqWgQGsiWTpyhdIkSSiO0hMKr_5oNNecp254CSO_zEPS6wWKMNwwZRteKIPzPafCkXvmGEuQo716CL9OP5T8BR25sXkws0llygfbbSK2dTWVN4lhM1Rm6zFJ4aK0BZo6EXDp0E0Od8SQSN7FooRAWOiO7HvjgpIdRyqkANElBSL7aNdsPP7dgVMua5P6MNfVjKCe93C-iqsOVadUV5UM3oblf6M_KkDV9GNr6oAizfrXHpPnHjG29u-DSsmCbLimgZaJ3LDnLrmzxbbl9b4mHJQqe00rNDUF6Q6BmmDgJGDMdPH4J8i6w_1z4Xll8Ul-UGHS6rJZeTVsEdKGSOoIbhQa9iuGxC_I_YIjkVbV3O8LcYBzDKetzups4R5CVFpwvAK03UCdM7yLkbDglWcSOYtbPVBafumCzyjWX9u7CpBAcVWe9KpEMVCYgi90TSkX2Vw1bPP07mTBFmK0fwmU2ZlDR0S9Q2NT9St7zWP6teuOeue7PAFlPUVotFdoh8ltZVLEfUTo81E1tiNycDCy9QTP9CzwplqpPIkmTdjmMCO6lollLrTm9SuXGp2FSUdE43tYEzRGNqsGpcwskkvzQWtl7bETaS5vCwPH76k6qGf-TpOHnOH1G7vDzDkewqJ-oscqwkdw4ONo_KxT-CGwv-JwMoSXWEtMKE",
              "e": "AQAB",
              "x5c": [
                "MIIElTCCAn0CBgF95wKLoDANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANkZXYwHhcNMjExMjIzMTExNTQzWhcNMzExMjIzMTExNzIzWjAOMQwwCgYDVQQDDANkZXYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDHg0c2mbM6CpaBAayJZOnKF0iRJKI7SEwqv/mg015ynbngJI7/MQ9LrBYow3DBlG14og/M9p8KRe+YYS5CjvXoIv04/lPwFHbmxeTCzSWXKB9ttIrZ1NZU3iWEzVGbrMUnhorQFmjoRcOnQTQ53xJBI3sWihEBY6I7se+OCkh1HKqQA0SUFIvto12w8/t2BUy5rk/ow19WMoJ73cL6Kqw5Vp1RXlQzehuV/oz8qQNX0Y2vqgCLN+tcek+ceMbb274NKyYJsuKaBloncsOcuubPFtuX1viYclCp7TSs0NQXpDoGaYOAkYMx08fgnyLrD/XPheWXxSX5QYdLqsll5NWwR0oZI6ghuFBr2K4bEL8j9giORVtXc7wtxgHMMp63O6mzhHkJUWnC8ArTdQJ0zvIuRsOCVZxI5i1s9UFp+6YLPKNZf27sKkEBxVZ70qkQxUJiCL3RNKRfZXDVs8/TuZMEWYrR/CZTZmUNHRL1DY1P1K3vNY/q1645657s8AWU9RWi0V2iHyW1lUsR9ROjzUTW2I3JwMLL1BM/0LPCmWqk8iSZN2OYwI7qWiWUutOb1K5canYVJR0Tje1gTNEY2qwalzCySS/NBa2XtsRNpLm8LA8fvqTqoZ/5Ok4ec4fUbu8PMOR7Con6ixyrCR3Dg42j8rFP4IbC/4nAyhJdYS0woQIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCr+GGCVS/sBHukLZay8WlBXtowJ6qyX8hMFClDGDN9/c3mUbLJsCCVN6Jbr33BgNZ/ZuvLhUvhWGPlOXUB3Rf+qRzNEzoLVwanw2yCUEKFi6AvuBUY9twNnifH4y1Cg34NVaZoPvQ0hlOLGYl9CCxen7VMLJ5QbTC8H3fPX1prWOic5x46Bu7IqoEqZtDszt8F+uteruRsHVHCiWx5dW7goeIa8YsUK0A4mnOy5kViSvs5L6Kq0N5uCB9EDu/Ew5R0/mi/UTm5L8CpzQig1pmvDtIy7ZnosHu7zYGSQiR04jn3Od0rdWzTCcs8W79+ewgJ0bdYmfvSnVehs1BR+cjivzBqMWMqdyz6eQXCy/esiG5KDIxH4F0HGLiiwXqHUYjJPex8TId+fz0MFScrEN5fjE+XltGzsPwlcgnAqE0pN0ExJSHwzBHNkJJQpjHrsEurWn9QGBqD75Vt9yVeHE8MZ4zMGj3ZkRmn1x6wVBdv1V12P3e4b8V5aG02FbREkJzFTXtGyDHtw/hlWGz9M9w0c5TAI6xYPa1gS6/Fw95J6S0V3n3JH+xqi6yv2H2cQHukFxFSPJW1cc/hh5DJ4Ag8+pKuO1Vdo9p+DltaGLWBabON7GZZojlYdx2WtBZK9CMRgrxobg+OBA44AHkiWkhflrqGLYul866wiNu6zLEfdQ=="
              ],
              "x5t": "0lMdqEAhOWfUXDivtS-KwPvwKNY",
              "x5t#S256": "aOjQ1awJmcaF7Yiz75ifjBKbjr4Eo-Ha5uNMi-TtuGw"
            },
            {
              "kid": "VlsIs1LssBo6r8EuXJo81rDEoTYpUjiMkeq_PlapKfY",
              "kty": "EC",
              "alg": "ES256",
              "use": "sig",
              "crv": "P-256",
              "x": "3kqy7us0mepJJblWwj0Exg2S7PtWaJvB7SI_ptg0jrA",
              "y": "S5Z8d4AfCvRL-hUd6Pv-L3tH6H9T4RIwO2tvBS0hj1A"
            },
            {
              "kid": "1yWLiqf8sa-em0hSbtZEjKmrardmQdYLR9gpzsypMCU",
              "kty": "EC",
              "alg": "ES384",
              "use": "sig",
              "crv": "P-384",
              "x": "i4YYGQZd5QQ1JpUXcrZe5wpCid3pqFLnzxxy89Chn-NQ1oYDPTP2M8V9sfazeuB0",
              "y": "xf4qN2ZuMLVh4GmRVt1PHhQooB2o61pF0lHrBlIod5hVamiRtUo_Np9PikPD8Uap"
            },
            {
              "kid": "V5EwcLp9vmwAnstzI1Ndba-iWkX5oTBHK7GnYTyfuOE",
              "kty": "EC",
              "alg": "ES512",
              "use": "sig",
              "crv": "P-521",
              "x": "rScgdd_n2cHLyzZvP8zw0u9vQyhu0VsbfQypheS7aDoHRLcXccPQTsmrQLrLuKX8PPkITjL_BJDSm7Bo8gv5Sd4",
              "y": "Vu3rTFNn_9zWTki95UGT1Bd9PN84KDXmttCrJ1bsYHTWQCaEONk8iwA3U6mEDrg4xtZSTXXKCFdFP13ONWB9oZ4"
            }
          ]
        });

        let jwks: PublicJsonWebKeySet = serde_json::from_value(jwks).unwrap();
        // The first 6 keys are RSA, 7th is P-256
        let mut keys = jwks.keys.into_iter();
        rsa::RsaPublicKey::try_from(keys.next().unwrap().params().rsa().unwrap()).unwrap();
        rsa::RsaPublicKey::try_from(keys.next().unwrap().params().rsa().unwrap()).unwrap();
        rsa::RsaPublicKey::try_from(keys.next().unwrap().params().rsa().unwrap()).unwrap();
        rsa::RsaPublicKey::try_from(keys.next().unwrap().params().rsa().unwrap()).unwrap();
        rsa::RsaPublicKey::try_from(keys.next().unwrap().params().rsa().unwrap()).unwrap();
        rsa::RsaPublicKey::try_from(keys.next().unwrap().params().rsa().unwrap()).unwrap();
        // 7th is P-256
        elliptic_curve::PublicKey::<p256::NistP256>::try_from(
            keys.next().unwrap().params().ec().unwrap(),
        )
        .unwrap();
        // 8th is P-384
        elliptic_curve::PublicKey::<p384::NistP384>::try_from(
            keys.next().unwrap().params().ec().unwrap(),
        )
        .unwrap();
        // 8th is P-521, but we don't support it yet
        keys.next().unwrap().params().ec().unwrap();
    }
}
