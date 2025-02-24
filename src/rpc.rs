use std::num::NonZero;
use std::time::Duration;

use reqwest::{self, Url, StatusCode};

use tokio::task::JoinSet;

use crate::timestamp::{Timestamp, TimestampBuilder};

pub const DEFAULT_AGGREGATORS: &[&str] = &["https://a.pool.opentimestamps.org",
                                          "https://b.pool.opentimestamps.org",
                                          "https://a.pool.eternitywall.com",
                                          "https://ots.btc.catallaxy.com"];

// FIXME: is this a reasonable length? from python-opentimestamps. But it's kinda big.
pub const MAX_STAMP_LENGTH: usize = 10_000;

#[derive(Debug)]
pub struct StampError {
    ts: TimestampBuilder,
}

#[derive(Debug, Clone)]
pub struct StampOptions {
    aggregators: Vec<Url>,
    min_attestations: NonZero<usize>,
    timeout: Duration,
}

impl Default for StampOptions {
    fn default() -> Self {
        Self {
            aggregators: DEFAULT_AGGREGATORS.iter().map(|s| Url::parse(s).expect("valid URL"))
                                                   .collect(),
            min_attestations: NonZero::new(2).unwrap(),
            timeout: Duration::from_secs(5),
        }
    }
}

pub async fn stamp(
    ts: TimestampBuilder,
    options: &StampOptions,
) -> Result<Timestamp, StampError> {
    todo!()
}

#[derive(Debug, thiserror::Error)]
pub enum PostDigestError {
    #[error("bad status code {0:?}")]
    BadStatus(reqwest::StatusCode),

    #[error("length limit exceeded")]
    LengthLimitExceeded,

    #[error("{0}")]
    Post(#[from] reqwest::Error),
}

async fn post_digest(
    digest: [u8; 32],
    aggregator: Url,
) -> Result<Timestamp<[u8; 32]>, PostDigestError> {
    let url = aggregator.join("digest").unwrap();
    let client = reqwest::Client::new();

    let response = client.post(url)
                         .header("User-Agent", "rust-opentimestamps")
                         .body(Vec::from(&digest[..]))
                         .send().await?;
    if response.status() != StatusCode::OK {
        return Err(PostDigestError::BadStatus(response.status()));
    }

    // FIXME: actually enforce this properly
    if response.content_length().unwrap_or(0) > MAX_STAMP_LENGTH as u64 {
        return Err(PostDigestError::LengthLimitExceeded);
    }

    let serialized = response.bytes().await?;
    match Timestamp::deserialize(digest, &mut &serialized[..]) {
        Ok(ts) => Ok(ts),
        Err(_) => todo!(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TimestampDigestError {
    #[error("insufficient responses")]
    InsufficientResponses {
        failures: Vec<PostDigestError>,
    }
}


async fn stamp_with_options(digest: [u8; 32], options: StampOptions) -> Result<Timestamp<[u8; 32]>, TimestampDigestError> {
    let mut set = JoinSet::new();

    for aggregator in options.aggregators.into_iter() {
        set.spawn(tokio::time::timeout(options.timeout, post_digest(digest, aggregator)));
    }

    let mut successes = vec![];
    let mut failures = vec![];
    while let Some(r) = set.join_next().await {
        match r.expect("post_digest task panicked")
               .expect("FIXME: handle timeouts")
        {
            Ok(ts) => {
                successes.push(ts);
            },
            Err(err) => {
                failures.push(err);
            }
        }
    }

    if successes.len() >= options.min_attestations.get() {
        Ok(TimestampBuilder::new(digest)
                            .finish_with_timestamps(successes))
    } else {
        Err(TimestampDigestError::InsufficientResponses {
            failures
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_post_digest() -> Result<(), Box<dyn std::error::Error>> {
        let url = Url::try_from("https://a.pool.opentimestamps.org/digest").unwrap();
        let ts = post_digest([0; 32], url).await?;
        dbg!(ts);
        Ok(())
    }

    #[tokio::test]
    async fn test_stamp_with_options() -> Result<(), Box<dyn std::error::Error>> {
        dbg!(stamp_with_options([0; 32], StampOptions::default()).await?);
        Ok(())
    }
}
