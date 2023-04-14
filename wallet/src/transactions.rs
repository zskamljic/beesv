use std::collections::HashMap;

use anyhow::Result;
use gloo_net::http::Request;
use serde::{Deserialize, Serialize};

use crate::{bip32::XPub, ratelimit::RateLimiter, util::log};

#[derive(Serialize)]
struct AddressHistoryRequest {
    addresses: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AddressHistory {
    address: String,
    history: Vec<TransactionInfo>,
}

#[derive(Debug, Deserialize)]
struct TransactionInfo {
    tx_hash: String,
}

pub async fn fetch_for_address(xpub: &XPub) -> Result<()> {
    let mut rate_limiter = RateLimiter::new(3);
    let mut last_tx_index: u32 = 0;
    loop {
        rate_limiter.take().await;
        let addresses: Vec<_> = (last_tx_index..last_tx_index + 20)
            .map(|i| {
                xpub.derive(i)
                    .expect("Derivation should succeed")
                    .to_address()
            })
            .collect();
        let transactions = fetch_chunk(&addresses).await?;
        last_tx_index += last_tx_address(&addresses, &transactions);
        if last_tx_index % 20 != 0 {
            break;
        }
    }

    log(&format!("First {last_tx_index} addresses were used"));

    Ok(())
}

async fn fetch_chunk(chunk: &[String]) -> Result<Vec<AddressHistory>> {
    let body = serde_json::to_string(&AddressHistoryRequest {
        addresses: chunk.to_vec(),
    })
    .unwrap();
    Request::post("https://api.whatsonchain.com/v1/bsv/main/addresses/history")
        .body(body)
        .send()
        .await?
        .json()
        .await
        .map_err(|e| e.into())
}

fn last_tx_address(chunk: &[String], transactions: &[AddressHistory]) -> u32 {
    let transactions_by_address: HashMap<String, Vec<String>> = transactions
        .iter()
        .map(|entry| {
            (
                entry.address.to_string(),
                entry
                    .history
                    .iter()
                    .map(|h| h.tx_hash.to_string())
                    .collect(),
            )
        })
        .collect();
    for i in 0..chunk.len() {
        if transactions_by_address[&chunk[i]].is_empty() {
            return i as u32;
        }
    }

    chunk.len() as u32
}
