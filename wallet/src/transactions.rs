use std::collections::HashMap;

use anyhow::Result;
use gloo_net::http::Request;
use serde::{Deserialize, Serialize};

use crate::{bip32::XPub, ratelimit::RateLimiter, util::log};

pub struct WalletState {
    main: FetchingState,
    change: FetchingState,
    pub balance: u64,
}

pub async fn fetch_for_address(xpub: &XPub, rate_limiter: &mut RateLimiter) -> Result<WalletState> {
    let xpub_main = xpub.derive(0)?;
    let xpub_change = xpub.derive(1)?;

    let main = fetch_used_data(xpub_main, rate_limiter).await?;
    let change = fetch_used_data(xpub_change, rate_limiter).await?;

    let active_addresses: Vec<_> = main
        .active_addresses
        .iter()
        .cloned()
        .chain(change.active_addresses.iter().cloned())
        .collect();

    let mut balance = 0u64;
    for chunk in active_addresses.chunks(20) {
        rate_limiter.take().await;
        let unspent_outputs = fetch_unspent_outputs(chunk).await?;
        balance += unspent_outputs
            .iter()
            .flat_map(|r| r.unspent.iter())
            .map(|o| o.value)
            .sum::<u64>();
    }

    Ok(WalletState {
        main,
        change,
        balance,
    })
}

struct FetchingState {
    xpub: XPub,
    last_index: u32,
    active_addresses: Vec<String>,
    transactions: Vec<String>,
}

async fn fetch_used_data(xpub: XPub, rate_limiter: &mut RateLimiter) -> Result<FetchingState> {
    let mut last_index: u32 = 0;
    let mut transactions = vec![];
    let mut active_addresses = vec![];
    loop {
        rate_limiter.take().await;
        let addresses: Vec<_> = (last_index..last_index + 20)
            .map(|i| {
                xpub.derive(i)
                    .expect("Derivation should succeed")
                    .to_address()
            })
            .collect();
        active_addresses.extend(addresses.clone());
        let history = fetch_transactions_for_addresses(&addresses).await?;
        history
            .iter()
            .flat_map(|a| a.history.iter())
            .map(|t| t.tx_hash.to_owned())
            .for_each(|t| transactions.push(t));

        last_index += last_tx_address(&addresses, &history);
        if last_index % 20 != 0 {
            break;
        }
    }
    Ok(FetchingState {
        xpub,
        last_index,
        active_addresses,
        transactions,
    })
}

#[derive(Serialize)]
struct AddressRequest {
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

async fn fetch_transactions_for_addresses(chunk: &[String]) -> Result<Vec<AddressHistory>> {
    let body = serde_json::to_string(&AddressRequest {
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
        txids: hashes.to_vec(),
    })?;

    Request::post("https://api.whatsonchain.com/v1/bsv/main/txs/hex")
        .body(body)
        .send()
        .await?
        .json()
        .await
        .map_err(|e| e.into())
}

#[derive(Debug, Deserialize)]
struct UtxoResponse {
    address: String,
    unspent: Vec<UnspentOutput>,
}

#[derive(Debug, Deserialize)]
struct UnspentOutput {
    height: u64,
    tx_pos: u32,
    tx_hash: String,
    value: u64,
}

async fn fetch_unspent_outputs(addresses: &[String]) -> Result<Vec<UtxoResponse>> {
    let body = serde_json::to_string(&AddressRequest {
        addresses: addresses.to_vec(),
    })?;

    Request::post("https://api.whatsonchain.com/v1/bsv/main/addresses/unspent")
        .body(body)
        .send()
        .await?
        .json()
        .await
        .map_err(|e| e.into())
}
