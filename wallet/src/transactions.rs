use std::collections::HashMap;

use anyhow::Result;
use gloo_net::http::Request;
use serde::{Deserialize, Serialize};

use crate::util::log;

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

pub async fn fetch_for_address(addresses: &[String]) -> Result<()> {
    let mut last_tx_index = 0;
    for chunk in addresses.chunks(20) {
        let transactions = fetch_chunk(chunk).await?;
        last_tx_index += last_tx_address(chunk, &transactions);
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

fn last_tx_address(chunk: &[String], transactions: &[AddressHistory]) -> usize {
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
            return i;
        }
    }

    chunk.len()
}
