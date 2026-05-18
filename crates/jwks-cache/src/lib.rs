// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Shared JWKS cache: HTTP fetch + Postgres-backed cache + per-URI request
//! coalescer.
//!
//! Each MAS process owns one `JwksFetcher` actor. Handlers call
//! [`JwksFetcher::get`] when they need a JWKS for signature verification; the
//! actor coalesces concurrent calls for the same URI into one HTTP fetch.
//! Across replicas, the `forced_refresh_at` column in the `jwks_cache` table
//! gates kid-miss and stale-while-revalidate refreshes to a fixed rate per
//! URI per fleet — replicas don't need to talk to each other.
//!
//! The cache is content-addressed by URI. Trust decisions about which keys
//! are acceptable for which purpose live one layer up and consume the actor's
//! output rather than influencing what gets cached.

#![deny(clippy::future_not_send, missing_docs)]
#![allow(clippy::module_name_repetitions)]

use std::{collections::HashMap, sync::Arc};

use chrono::Duration;
use http::{
    StatusCode,
    header::{CACHE_CONTROL, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED},
};
use mas_data_model::{Clock, JwksCacheEntry};
use mas_http::RequestBuilderExt;
use mas_iana::jose::JsonWebSignatureAlg;
use mas_jose::jwk::PublicJsonWebKeySet;
use mas_storage::{
    RepositoryAccess, RepositoryFactory,
    jwks_cache::JwksCacheUpsert,
};
use thiserror::Error;
use tokio::{
    sync::{mpsc, mpsc::WeakSender, oneshot},
    task::JoinHandle,
};
use tracing::{Instrument, Span};
use url::Url;

// === Crate-level constants. Per the plan these stay un-tuneable until a real
// deployment surfaces a concrete need — the values are bounded by JWT `exp`
// either way, so defense-in-depth tuning isn't compelling. ===

/// Lower bound for `Cache-Control: max-age`. A publisher sending `max-age=0`
/// (or `no-store` / `private`, which we treat the same as `max-age=0`) would
/// otherwise defeat the cache entirely.
const MIN_TTL: Duration = Duration::seconds(60);

/// Upper bound for `Cache-Control: max-age`. JWT lifetimes typically range
/// from minutes to hours; capping the JWKS cache below the longest-lived
/// JWT type means a rotated-out key stops being honoured promptly even if
/// the publisher told us to cache for longer.
const MAX_TTL: Duration = Duration::hours(6);

/// Upper bound for `Cache-Control: stale-while-revalidate`.
const MAX_SWR: Duration = Duration::hours(1);

/// TTL used when the response has no `Cache-Control` directive.
const DEFAULT_TTL: Duration = Duration::minutes(15);

/// HTTP request timeout per fetch attempt.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Maximum body size in bytes. Real JWKS are kilobytes; anything larger is
/// misbehaving or hostile.
const MAX_BODY_SIZE: u64 = 1_048_576;

/// Bound on the actor's inbound queue, so request handlers experience natural
/// backpressure under absurd load rather than the queue itself becoming the
/// failure mode.
const FETCHER_QUEUE_SIZE: usize = 1024;

/// Threshold below which the read path will lazy-bump `last_used_at`. Reads
/// within this many minutes of the previous bump don't trigger another write.
const TOUCH_THRESHOLD: Duration = Duration::minutes(5);

/// Errors surfaced by the fetcher to callers of [`JwksFetcher::get`].
#[derive(Debug, Error)]
pub enum FetcherError {
    /// The HTTP request failed (timeout, DNS, TLS, body read, …).
    #[error("HTTP request to {uri} failed")]
    Http {
        /// The URI that was being fetched.
        uri: Url,
        /// The underlying transport error.
        #[source]
        source: reqwest::Error,
    },

    /// The origin returned a non-success status and we had no usable cached
    /// body to fall back on.
    #[error("HTTP {status} from {uri}")]
    Status {
        /// The URI that was being fetched.
        uri: Url,
        /// The status code returned by the origin.
        status: StatusCode,
    },

    /// The response body exceeded [`MAX_BODY_SIZE`].
    #[error("response from {uri} exceeded {max} bytes")]
    BodyTooLarge {
        /// The URI that was being fetched.
        uri: Url,
        /// The body-size cap.
        max: u64,
    },

    /// The response body was not parseable as a JWKS.
    #[error("failed to parse JWKS from {uri}")]
    Parse {
        /// The URI that was being fetched.
        uri: Url,
        /// The underlying parse error.
        #[source]
        source: serde_json::Error,
    },

    /// A repository operation failed.
    #[error("storage error while caching JWKS for {uri}")]
    Repository {
        /// The URI that was being fetched.
        uri: Url,
        /// The underlying storage error.
        #[source]
        source: mas_storage::RepositoryError,
    },

    /// The fetcher actor task is no longer running. This is observable only
    /// during shutdown.
    #[error("JWKS fetcher actor is no longer running")]
    ActorGone,
}

/// Result type fanned out to coalesced waiters. Each variant is wrapped in an
/// `Arc` so success and error both fan out by refcount-bump rather than
/// `Clone` — `FetcherError` is not (and need not be) `Clone`, and a JWKS body
/// is non-trivial to copy.
pub type FetchResult = Result<Arc<PublicJsonWebKeySet>, Arc<FetcherError>>;

/// A transparent `std::error::Error` wrapper around `Arc<FetcherError>`. Useful
/// at call sites that need to bubble the error up through trait objects like
/// `Box<dyn Error + Send + Sync>`.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct SharedFetcherError(#[from] pub Arc<FetcherError>);

/// A handle to the fetcher actor. Cheap to clone (just an `mpsc::Sender`).
#[derive(Clone)]
pub struct JwksFetcher {
    tx: mpsc::Sender<FetchRequest>,
}

impl JwksFetcher {
    /// Start a fetcher actor and return a handle plus its [`JoinHandle`].
    /// The actor terminates cleanly when all handles are dropped.
    #[must_use]
    pub fn start(
        http: reqwest::Client,
        factory: Arc<dyn RepositoryFactory + Send + Sync>,
        clock: Arc<dyn Clock>,
    ) -> (Self, JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(FETCHER_QUEUE_SIZE);
        // The actor only holds a WeakSender — it can self-message for SWR
        // refreshes when caller handles still exist, but doesn't itself keep
        // the channel alive. When all `JwksFetcher` clones drop, `rx.recv()`
        // returns `None` and the actor shuts down.
        let weak = tx.downgrade();
        let handle = tokio::spawn(run_fetcher(rx, weak, http, factory, clock));
        (Self { tx }, handle)
    }

    /// Get the JWKS for `uri`, fetching if needed per cache rules.
    ///
    /// Concurrent calls for the same URI are coalesced: they share one HTTP
    /// fetch (and one returned `Arc<Result<…>>`).
    ///
    /// # Errors
    ///
    /// Returns [`FetcherError::ActorGone`] only if the actor task has
    /// terminated (process shutdown). All other errors are wrapped inside the
    /// `Arc<Result<…>>`.
    pub async fn get(&self, uri: Url) -> Result<FetchResult, FetcherError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(FetchRequest::Get {
                uri,
                respond_to: tx,
                span: Span::current(),
            })
            .await
            .map_err(|_| FetcherError::ActorGone)?;
        rx.await.map_err(|_| FetcherError::ActorGone)
    }

    /// Trigger a forced refresh for `uri`. Fire-and-forget.
    ///
    /// Used after a verifier detects a kid miss and has already claimed the
    /// cross-replica cooldown on `forced_refresh_at`. The caller does the
    /// claim because their request transaction owns it; the actor's worker
    /// then performs the network fetch without re-claiming.
    pub fn refresh(&self, uri: Url) {
        // `try_send` so this is truly fire-and-forget. If the queue is full,
        // we drop the refresh; the next call site that finds the cache stale
        // will trigger another refresh anyway.
        let _ = self.tx.try_send(FetchRequest::Refresh {
            uri,
            span: Span::current(),
        });
    }
}

enum FetchRequest {
    Get {
        uri: Url,
        respond_to: oneshot::Sender<FetchResult>,
        span: Span,
    },
    Refresh {
        uri: Url,
        span: Span,
    },
}

struct UriState {
    waiters: Vec<oneshot::Sender<FetchResult>>,
}

fn clone_result(r: &FetchResult) -> FetchResult {
    match r {
        Ok(arc) => Ok(Arc::clone(arc)),
        Err(arc) => Err(Arc::clone(arc)),
    }
}

/// Determines whether the spawned worker treats a cache hit as a return-as-is
/// (Get) or as a candidate for inline revalidation (Refresh).
#[derive(Debug, Clone, Copy)]
enum WorkerMode {
    /// Cache-aware: return the fresh body, schedule SWR if stale, fetch if
    /// expired.
    Get,
    /// Always attempt a conditional GET regardless of `fresh_until`.
    Refresh,
}

async fn run_fetcher(
    mut rx: mpsc::Receiver<FetchRequest>,
    tx_self: WeakSender<FetchRequest>,
    http: reqwest::Client,
    factory: Arc<dyn RepositoryFactory + Send + Sync>,
    clock: Arc<dyn Clock>,
) {
    let mut in_flight: HashMap<Url, UriState> = HashMap::new();
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<(Url, FetchResult)>();

    loop {
        tokio::select! {
            biased;

            // Worker completions take priority so coalesced waiters are
            // unblocked before the actor consumes more inbound requests.
            Some((uri, result)) = done_rx.recv() => {
                if let Some(state) = in_flight.remove(&uri) {
                    for w in state.waiters {
                        let _ = w.send(clone_result(&result));
                    }
                }
            },
            req = rx.recv() => {
                let Some(req) = req else { break };
                match req {
                    FetchRequest::Get { uri, respond_to, span } => {
                        let state = in_flight.entry(uri.clone()).or_insert_with(|| {
                            spawn_worker(
                                uri.clone(),
                                WorkerMode::Get,
                                http.clone(),
                                Arc::clone(&factory),
                                Arc::clone(&clock),
                                tx_self.clone().upgrade(),
                                done_tx.clone(),
                                &span,
                            );
                            UriState { waiters: Vec::new() }
                        });
                        state.waiters.push(respond_to);
                    }
                    FetchRequest::Refresh { uri, span } => {
                        in_flight.entry(uri.clone()).or_insert_with(|| {
                            spawn_worker(
                                uri.clone(),
                                WorkerMode::Refresh,
                                http.clone(),
                                Arc::clone(&factory),
                                Arc::clone(&clock),
                                tx_self.clone().upgrade(),
                                done_tx.clone(),
                                &span,
                            );
                            UriState { waiters: Vec::new() }
                        });
                    }
                }
            },
            else => break,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_worker(
    uri: Url,
    mode: WorkerMode,
    http: reqwest::Client,
    factory: Arc<dyn RepositoryFactory + Send + Sync>,
    clock: Arc<dyn Clock>,
    tx_self: Option<mpsc::Sender<FetchRequest>>,
    done_tx: mpsc::UnboundedSender<(Url, FetchResult)>,
    span: &Span,
) {
    let worker_span = tracing::info_span!(
        parent: span,
        "jwks_fetcher.worker",
        otel.kind = "internal",
        jwks_uri = %uri,
        ?mode,
    );
    let uri_for_done = uri.clone();
    tokio::spawn(
        async move {
            let result = run_worker(uri.clone(), mode, http, factory, clock, tx_self)
                .await
                .map(Arc::new)
                .map_err(Arc::new);
            // If the receiver has been dropped (handler timed out) the result
            // is still useful — the upsert already updated the DB cache.
            let _ = done_tx.send((uri_for_done, result));
        }
        .instrument(worker_span),
    );
}

async fn run_worker(
    uri: Url,
    mode: WorkerMode,
    http: reqwest::Client,
    factory: Arc<dyn RepositoryFactory + Send + Sync>,
    clock: Arc<dyn Clock>,
    tx_self: Option<mpsc::Sender<FetchRequest>>,
) -> Result<PublicJsonWebKeySet, FetcherError> {
    let now = clock.now();
    let repo_err = |source: mas_storage::RepositoryError| FetcherError::Repository {
        uri: uri.clone(),
        source,
    };

    // Read current state from the DB cache (and lazy-bump last_used_at if
    // we'll be returning the cached body straight away).
    let mut repo = factory.create().await.map_err(repo_err)?;
    let entry = repo.jwks_cache().get(&uri).await.map_err(repo_err)?;

    if let (WorkerMode::Get, Some(entry_ref)) = (mode, entry.as_ref()) {
        if entry_ref.is_fresh(now) {
            let cached = entry_ref.jwks.clone();
            let threshold = now - TOUCH_THRESHOLD;
            repo.jwks_cache()
                .touch(&uri, now, threshold)
                .await
                .map_err(repo_err)?;
            repo.save().await.map_err(repo_err)?;
            return Ok(cached);
        }
        if entry_ref.is_stale_but_servable(now) {
            let cached = entry_ref.jwks.clone();
            let threshold = now - TOUCH_THRESHOLD;
            repo.jwks_cache()
                .touch(&uri, now, threshold)
                .await
                .map_err(repo_err)?;
            repo.save().await.map_err(repo_err)?;
            // Schedule a background refresh. If the queue is full or the
            // actor has already shut down, drop it — another request will
            // trigger one soon enough.
            if let Some(tx) = &tx_self {
                let _ = tx.try_send(FetchRequest::Refresh {
                    uri: uri.clone(),
                    span: Span::current(),
                });
            }
            return Ok(cached);
        }
    }

    // We're going to make an HTTP request — release the read transaction now
    // so we're not holding a Postgres connection during the network roundtrip.
    repo.cancel().await.map_err(repo_err)?;

    let outcome = fetch_remote(&http, &uri, entry.as_ref()).await?;
    let now = clock.now();

    let (jwks_to_persist, cache_control) = match outcome {
        FetchOutcome::Body { jwks, cache_control } => (Some(jwks), cache_control),
        FetchOutcome::NotModified { cache_control } => (None, cache_control),
        FetchOutcome::ErrorWithCached => {
            // Stale-on-error: serve the cached body, log a warning, and leave
            // freshness windows unchanged so the next request retries sooner.
            let entry = entry.expect("ErrorWithCached requires a prior entry");
            tracing::warn!(
                jwks_uri = %uri,
                "Serving stale cached JWKS after upstream returned an error"
            );
            return Ok(entry.jwks);
        }
        FetchOutcome::Error(err) => return Err(err),
    };

    let fresh_until = now + cache_control.max_age;
    let stale_until = cache_control.swr.map(|swr| fresh_until + swr);

    let final_jwks = match (jwks_to_persist, entry) {
        (Some(jwks), _) => jwks,
        (None, Some(entry)) => entry.jwks,
        // 304 without a prior entry is impossible (we wouldn't have sent
        // If-None-Match), but guard against it anyway.
        (None, None) => {
            return Err(FetcherError::Status {
                uri,
                status: StatusCode::NOT_MODIFIED,
            });
        }
    };

    let mut repo = factory.create().await.map_err(repo_err)?;
    repo.jwks_cache()
        .upsert(
            &uri,
            JwksCacheUpsert {
                jwks: &final_jwks,
                fetched_at: now,
                fresh_until,
                stale_until,
                etag: cache_control.etag.as_deref(),
                last_modified: cache_control.last_modified.as_deref(),
            },
        )
        .await
        .map_err(repo_err)?;
    repo.save().await.map_err(repo_err)?;

    Ok(final_jwks)
}

#[derive(Debug, Default)]
struct CacheControlDirectives {
    max_age: Duration,
    swr: Option<Duration>,
    etag: Option<String>,
    last_modified: Option<String>,
}

enum FetchOutcome {
    Body {
        jwks: PublicJsonWebKeySet,
        cache_control: CacheControlDirectives,
    },
    NotModified {
        cache_control: CacheControlDirectives,
    },
    /// The fetch failed but we have a cached entry to serve stale.
    ErrorWithCached,
    /// The fetch failed and we don't have anything to fall back on.
    Error(FetcherError),
}

async fn fetch_remote(
    http: &reqwest::Client,
    uri: &Url,
    prior: Option<&JwksCacheEntry>,
) -> Result<FetchOutcome, FetcherError> {
    let mut request = http.get(uri.as_str()).timeout(REQUEST_TIMEOUT);
    if let Some(entry) = prior {
        if let Some(etag) = &entry.etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(lm) = &entry.last_modified {
            request = request.header(IF_MODIFIED_SINCE, lm);
        }
    }

    let response = match request.send_traced().await {
        Ok(r) => r,
        Err(source) => {
            return Ok(if prior.is_some() {
                FetchOutcome::ErrorWithCached
            } else {
                FetchOutcome::Error(FetcherError::Http {
                    uri: uri.clone(),
                    source,
                })
            });
        }
    };

    let status = response.status();

    if status == StatusCode::NOT_MODIFIED {
        let cache_control = read_cache_control_headers(&response, prior);
        return Ok(FetchOutcome::NotModified { cache_control });
    }

    if !status.is_success() {
        return Ok(if prior.is_some() {
            FetchOutcome::ErrorWithCached
        } else {
            FetchOutcome::Error(FetcherError::Status {
                uri: uri.clone(),
                status,
            })
        });
    }

    let cache_control = read_cache_control_headers(&response, prior);

    // Cap the response body. We don't trust `Content-Length` and pull bytes
    // ourselves until the cap.
    let mut bytes = Vec::with_capacity(8 * 1024);
    let mut stream = response;
    loop {
        let chunk = match stream.chunk().await {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(source) => {
                return Ok(if prior.is_some() {
                    FetchOutcome::ErrorWithCached
                } else {
                    FetchOutcome::Error(FetcherError::Http {
                        uri: uri.clone(),
                        source,
                    })
                });
            }
        };
        if (bytes.len() as u64) + (chunk.len() as u64) > MAX_BODY_SIZE {
            return Ok(if prior.is_some() {
                FetchOutcome::ErrorWithCached
            } else {
                FetchOutcome::Error(FetcherError::BodyTooLarge {
                    uri: uri.clone(),
                    max: MAX_BODY_SIZE,
                })
            });
        }
        bytes.extend_from_slice(&chunk);
    }

    let parsed: PublicJsonWebKeySet = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(source) => {
            return Ok(if prior.is_some() {
                FetchOutcome::ErrorWithCached
            } else {
                FetchOutcome::Error(FetcherError::Parse {
                    uri: uri.clone(),
                    source,
                })
            });
        }
    };

    let jwks = sanitize_jwks(&parsed);

    Ok(FetchOutcome::Body {
        jwks,
        cache_control,
    })
}

fn read_cache_control_headers(
    response: &reqwest::Response,
    prior: Option<&JwksCacheEntry>,
) -> CacheControlDirectives {
    let headers = response.headers();
    let cache_control_raw = headers
        .get(CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let parsed = parse_cache_control(cache_control_raw);

    let etag = headers
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| prior.and_then(|p| p.etag.clone()));

    let last_modified = headers
        .get(LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| prior.and_then(|p| p.last_modified.clone()));

    CacheControlDirectives {
        max_age: parsed.max_age,
        swr: parsed.swr,
        etag,
        last_modified,
    }
}

#[derive(Debug, Default)]
struct ParsedCacheControl {
    max_age: Duration,
    swr: Option<Duration>,
}

/// Parse the subset of [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111)
/// `Cache-Control` directives we care about (`max-age`,
/// `stale-while-revalidate`, `no-store`, `private`), applying the crate-level
/// clamps. JWKS endpoints that send `no-store` or `private` are misconfigured
/// — `no-store` would mean refetching on every request, defeating the cache.
/// We treat them as if they'd sent `max-age=MIN_TTL` and log a warning.
fn parse_cache_control(header: &str) -> ParsedCacheControl {
    let mut max_age: Option<Duration> = None;
    let mut swr: Option<Duration> = None;
    let mut suppress = false;

    for directive in header.split(',') {
        let directive = directive.trim();
        if directive.eq_ignore_ascii_case("no-store") || directive.eq_ignore_ascii_case("private") {
            suppress = true;
            continue;
        }
        let (name, value) = directive.split_once('=').unwrap_or((directive, ""));
        let value = value.trim().trim_matches('"');
        match name.trim().to_ascii_lowercase().as_str() {
            "max-age" => {
                if let Ok(seconds) = value.parse::<i64>() {
                    max_age = Some(Duration::seconds(seconds));
                }
            }
            "stale-while-revalidate" => {
                if let Ok(seconds) = value.parse::<i64>() {
                    swr = Some(Duration::seconds(seconds));
                }
            }
            _ => {}
        }
    }

    let max_age = if suppress {
        tracing::warn!(
            cache_control = header,
            "JWKS endpoint sent `no-store`/`private`; clamping to minimum TTL",
        );
        MIN_TTL
    } else {
        max_age.map_or(DEFAULT_TTL, |d| clamp(d, MIN_TTL, MAX_TTL))
    };

    let swr = swr.map(|d| clamp(d, Duration::zero(), MAX_SWR));

    ParsedCacheControl { max_age, swr }
}

fn clamp(d: Duration, min: Duration, max: Duration) -> Duration {
    if d < min {
        min
    } else if d > max {
        max
    } else {
        d
    }
}

/// Drop any keys that publish themselves as unsafe to use for verification.
/// `alg=none` is a rejection-at-fetch case; the public-parameters JWK enum
/// already excludes symmetric `oct` keys at parse time so they cannot enter
/// the cache regardless.
fn sanitize_jwks(jwks: &PublicJsonWebKeySet) -> PublicJsonWebKeySet {
    let filtered: Vec<_> = jwks
        .iter()
        .filter(|k| !matches!(k.alg(), Some(JsonWebSignatureAlg::None)))
        .cloned()
        .collect();
    PublicJsonWebKeySet::new(filtered)
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use mas_jose::constraints::Constrainable;

    use super::*;

    #[test]
    fn cache_control_max_age_clamped() {
        let p = parse_cache_control("public, max-age=300");
        assert_eq!(p.max_age, Duration::seconds(300));
        assert!(p.swr.is_none());

        let p = parse_cache_control("max-age=1");
        assert_eq!(p.max_age, MIN_TTL, "small max-age clamped up");

        let p = parse_cache_control("max-age=99999999");
        assert_eq!(p.max_age, MAX_TTL, "large max-age clamped down");
    }

    #[test]
    fn cache_control_default_ttl_on_no_header() {
        let p = parse_cache_control("");
        assert_eq!(p.max_age, DEFAULT_TTL);
        assert!(p.swr.is_none());
    }

    #[test]
    fn cache_control_no_store_treated_as_min_ttl() {
        let p = parse_cache_control("no-store");
        assert_eq!(p.max_age, MIN_TTL);

        let p = parse_cache_control("private, max-age=3600");
        assert_eq!(p.max_age, MIN_TTL);
    }

    #[test]
    fn cache_control_swr_parsed_and_clamped() {
        let p = parse_cache_control("max-age=60, stale-while-revalidate=120");
        assert_eq!(p.max_age, MIN_TTL);
        assert_eq!(p.swr, Some(Duration::seconds(120)));

        let p = parse_cache_control("max-age=300, stale-while-revalidate=99999999");
        assert_eq!(p.swr, Some(MAX_SWR), "swr clamped");
    }

    #[test]
    fn sanitize_drops_alg_none() {
        let raw = serde_json::json!({
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "k1",
                    "alg": "RS256",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB",
                },
                {
                    "kty": "RSA",
                    "kid": "k2",
                    "alg": "none",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB",
                },
            ]
        });
        let jwks: PublicJsonWebKeySet = serde_json::from_value(raw).unwrap();
        assert_eq!(jwks.len(), 2);
        let cleaned = sanitize_jwks(&jwks);
        assert_eq!(cleaned.len(), 1);
        assert_eq!(cleaned[0].kid(), Some("k1"));
    }
}
