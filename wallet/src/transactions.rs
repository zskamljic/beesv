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

pub async fn fetch_for_address(xpub: &XPub) -> Result<Vec<String>> {
    let mut transactions = vec![];
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
        let history = fetch_transactions_for_addresses(&addresses).await?;
        history
            .iter()
            .flat_map(|a| a.history.iter())
            .map(|t| t.tx_hash.to_owned())
            .for_each(|t| transactions.push(t));

        last_tx_index += last_tx_address(&addresses, &history);
        if last_tx_index % 20 != 0 {
            break;
        }
    }

    for chunk in transactions.chunks(20) {
        rate_limiter.take().await;
        let raw_transactions = fetch_raw_transactions(chunk).await?;
        log(&format!("Raw transactions: {raw_transactions:?}"));
    }

    Ok(transactions)
}

async fn fetch_transactions_for_addresses(chunk: &[String]) -> Result<Vec<AddressHistory>> {
    let body = serde_json::to_string(&AddressHistoryRequest {
        addresses: chunk.to_vec(),
    })?;
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

#[derive(Serialize)]
struct RawTransactionRequest {
    txids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawTransaction {
    txid: String,
    hex: String,
    blockhash: String,
    blockheight: u64,
    blocktime: u64,
    confirmations: u64,
}

async fn fetch_raw_transactions(hashes: &[String]) -> Result<Vec<RawTransaction>> {
    let body = serde_json::to_string(&RawTransactionRequest {
        txids: hashes.iter().cloned().collect(),
    })?;

    Request::post("https://api.whatsonchain.com/v1/bsv/main/txs/hex")
        .body(body)
        .send()
        .await?
        .json()
        .await
        .map_err(|e| e.into())
}
