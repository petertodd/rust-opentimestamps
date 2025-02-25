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

    #[error("deserialization error: {0}")]
    Deserialize(#[from] crate::ser::DeserializeError),
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
        Err(err) => Err(err.into()),
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

    use crate::timestamp::*;
    use crate::attestation::*;
    use crate::op::*;

    #[tokio::test]
    async fn test_post_digest() -> Result<(), Box<dyn std::error::Error>> {
        let mut server = mockito::Server::new_async().await;

        let expected_steps = vec![Step::Attestation(Attestation::Bitcoin { block_height: 42 })];
        let expected_steps = Steps::trust(expected_steps);

        let mock = server.mock("POST", "/digest")
                         .with_body(expected_steps.to_serialized_bytes())
                         .match_body(vec![42u8; 32])
                         .create_async().await;

        let url: &str = &server.url();
        let url = Url::try_from(url).unwrap();
        let ts = post_digest([42; 32], url).await?;

        assert_eq!(ts.steps(), &expected_steps);

        mock.assert_async().await;

        Ok(())
    }

    #[tokio::test]
    async fn test_post_digest_errors() -> Result<(), Box<dyn std::error::Error>> {
        let mut server = mockito::Server::new_async().await;
        let url: &str = &server.url();
        let url = Url::try_from(url).unwrap();

        let mock = server.mock("POST", "/digest")
                         .with_body("not found")
                         .with_status(404)
                         .match_body(vec![42u8; 32])
                         .create_async().await;

        match post_digest([42; 32], url.clone()).await {
            Err(PostDigestError::BadStatus(reqwest::StatusCode::NOT_FOUND)) => {},
            unexpected => panic!("{:?}", unexpected),
        };

        mock.assert_async().await;


        let mock = server.mock("POST", "/digest")
                         .with_body("not a timestamp")
                         .match_body(vec![43u8; 32])
                         .create_async().await;

        match post_digest([43; 32], url.clone()).await {
            Err(PostDigestError::Deserialize(_)) => {},
            unexpected => panic!("{:?}", unexpected),
        };

        mock.assert_async().await;


        let mut expected_steps = vec![Step::Op(Op::HashOp(HashOp::Sha256)); 10_000];
        expected_steps.push(Step::Attestation(Attestation::Bitcoin { block_height: 42 }));
        let expected_steps = Steps::trust(expected_steps);

        let mock = server.mock("POST", "/digest")
                         .with_body(expected_steps.to_serialized_bytes())
                         .match_body(vec![43u8; 32])
                         .create_async().await;

        match post_digest([43; 32], url.clone()).await {
            Err(PostDigestError::LengthLimitExceeded) => {},
            unexpected => panic!("{:?}", unexpected),
        };

        mock.assert_async().await;

        Ok(())
    }

    #[tokio::test]
    async fn test_stamp_with_options() -> Result<(), Box<dyn std::error::Error>> {
        let mut server1 = mockito::Server::new_async().await;
        let url1: &str = &server1.url();
        let url1 = Url::try_from(url1).unwrap();

        let expected_steps1 = vec![Step::Attestation(Attestation::Bitcoin { block_height: 42 })];
        let expected_steps1 = Steps::trust(expected_steps1);

        let mock1 = server1.mock("POST", "/digest")
                           .with_body(expected_steps1.to_serialized_bytes())
                           .create_async().await;

        let mut server2 = mockito::Server::new_async().await;
        let url2: &str = &server2.url();
        let url2 = Url::try_from(url2).unwrap();

        let expected_steps2 = vec![Step::Attestation(Attestation::Bitcoin { block_height: 43 })];
        let expected_steps2 = Steps::trust(expected_steps2);

        let mock2 = server2.mock("POST", "/digest")
                           .with_body(expected_steps2.to_serialized_bytes())
                           .create_async().await;

        let stamp_options = StampOptions {
            aggregators: vec![url1, url2],
            min_attestations: NonZero::new(2).unwrap(),
            timeout: Duration::from_secs(5),
        };

        // FIXME: validate that ts had the expected attestations in it
        let _ts = stamp_with_options([0; 32], stamp_options).await?;

        mock1.assert_async().await;
        mock2.assert_async().await;

        Ok(())
    }

    #[tokio::test]
    async fn test_stamp_with_options_partial_failure() -> Result<(), Box<dyn std::error::Error>> {
        let mut server1 = mockito::Server::new_async().await;
        let url1: &str = &server1.url();
        let url1 = Url::try_from(url1).unwrap();

        let expected_steps1 = vec![Step::Attestation(Attestation::Bitcoin { block_height: 42 })];
        let expected_steps1 = Steps::trust(expected_steps1);

        let mock1 = server1.mock("POST", "/digest")
                           .with_body(expected_steps1.to_serialized_bytes())
                           .create_async().await;

        let mut server2 = mockito::Server::new_async().await;
        let url2: &str = &server2.url();
        let url2 = Url::try_from(url2).unwrap();

        let mock2 = server2.mock("POST", "/digest")
                           .with_body("not a timestamp")
                           .create_async().await;

        let stamp_options = StampOptions {
            aggregators: vec![url1, url2],
            min_attestations: NonZero::new(1).unwrap(),
            timeout: Duration::from_secs(5),
        };

        let ts = stamp_with_options([0; 32], stamp_options).await?;
        assert_eq!(ts.steps(), &expected_steps1);

        mock1.assert_async().await;
        mock2.assert_async().await;

        Ok(())
    }

    #[tokio::test]
    async fn test_stamp_with_options_total_failure() -> Result<(), Box<dyn std::error::Error>> {
        let mut server1 = mockito::Server::new_async().await;
        let url1: &str = &server1.url();
        let url1 = Url::try_from(url1).unwrap();

        let mock1 = server1.mock("POST", "/digest")
                           .with_body("not a timestamp")
                           .create_async().await;

        let mut server2 = mockito::Server::new_async().await;
        let url2: &str = &server2.url();
        let url2 = Url::try_from(url2).unwrap();

        let mock2 = server2.mock("POST", "/digest")
                           .with_body("no found")
                           .with_status(404)
                           .create_async().await;

        let stamp_options = StampOptions {
            aggregators: vec![url1, url2],
            min_attestations: NonZero::new(1).unwrap(),
            timeout: Duration::from_secs(5),
        };

        match stamp_with_options([0; 32], stamp_options).await {
            Err(TimestampDigestError::InsufficientResponses { .. }) => {},
            unexpected => panic!("{:?}", unexpected),
        }

        mock1.assert_async().await;
        mock2.assert_async().await;

        Ok(())
    }
}
