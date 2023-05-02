use std::collections::HashMap;

use anyhow::Result;
use gloo_net::http::Request;
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

use crate::{bip32::XPrv, ratelimit::RateLimiter, util};

#[derive(Default)]
pub struct WalletState {
    main: FetchingState,
    change: FetchingState,
    pub balance: u64,
    pub unspent_outputs: Vec<RichOutput>,
}

#[derive(Clone, PartialEq)]
pub struct RichOutput {
    pub tx_pos: u32,
    pub tx_hash: String,
    pub amount: u64,
    pub address: [u8; 20],
}

impl WalletState {
    pub fn change_address(&self) -> String {
        self.change.next_address.clone()
    }

    pub fn address_keys(&self) -> HashMap<[u8; 20], (SecretKey, PublicKey)> {
        let mut keys = HashMap::new();
        keys.extend(self.main.lookup.clone());
        keys.extend(self.change.lookup.clone());
        keys
    }
}

pub async fn fetch_for_address(xprv: &XPrv, rate_limiter: &mut RateLimiter) -> Result<WalletState> {
    let xprv_main = xprv.derive(0);
    let xprv_change = xprv.derive(1);

    let main = fetch_used_data(xprv_main, rate_limiter).await?;
    let change = fetch_used_data(xprv_change, rate_limiter).await?;

    let active_addresses: Vec<_> = main
        .addresses()
        .iter()
        .cloned()
        .chain(change.addresses().iter().cloned())
        .collect();

    let mut balance = 0u64;
    let mut unspent_outputs = vec![];
    for chunk in active_addresses.chunks(20) {
        rate_limiter.take().await;
        let utxos = fetch_unspent_outputs(chunk).await?;
        balance += utxos
            .iter()
            .flat_map(|r| r.unspent.iter())
            .map(|o| o.value)
            .sum::<u64>();
        let rich_outputs: Result<Vec<_>> = utxos
            .into_iter()
            .flat_map(|r| r.unspent.into_iter().map(move |u| (r.address.clone(), u)))
            .map(|(address, unspent)| {
                Ok(RichOutput {
                    tx_pos: unspent.tx_pos,
                    tx_hash: unspent.tx_hash,
                    amount: unspent.value,
                    address: util::address_bytes(&address)?,
                })
            })
            .collect();

        unspent_outputs.extend(rich_outputs?);
    }

    Ok(WalletState {
        main,
        change,
        balance,
        unspent_outputs,
    })
}

struct FetchingState {
    xprv: XPrv,
    last_index: u32,
    lookup: HashMap<[u8; 20], (SecretKey, PublicKey)>,
    transactions: Vec<String>,
    next_address: String,
}

impl FetchingState {
    fn addresses(&self) -> Vec<String> {
        self.lookup.keys().cloned().map(util::to_address).collect()
    }
}

impl Default for FetchingState {
    fn default() -> Self {
        Self {
            xprv: XPrv::empty(),
            last_index: 0,
            lookup: HashMap::new(),
            transactions: vec![],
            next_address: String::default(),
        }
    }
}

async fn fetch_used_data(xprv: XPrv, rate_limiter: &mut RateLimiter) -> Result<FetchingState> {
    let mut last_index: u32 = 0;
    let mut transactions = vec![];
    let mut lookup = HashMap::new();
    let next_address: String;
    loop {
        rate_limiter.take().await;
        let addresses_lookup: HashMap<_, _> = (last_index..last_index + 20)
            .map(|i| {
                let key = xprv.derive(i);
                let key_pair = key.to_keypair();
                (key.derive_public().to_address(), key_pair)
            })
            .collect();
        let addresses: Vec<_> = addresses_lookup.keys().cloned().collect();
        let address_lookup: Result<HashMap<_, _>> = addresses_lookup
            .into_iter()
            .map(|(address, keys)| Ok((util::address_bytes(&address)?, keys)))
            .collect();
        lookup.extend(address_lookup?);
        let history = fetch_transactions_for_addresses(&addresses).await?;
        history
            .iter()
            .flat_map(|a| a.history.iter())
            .map(|t| t.tx_hash.to_owned())
            .for_each(|t| transactions.push(t));

        last_index += last_tx_address(&addresses, &history);
        if last_index == 0 || last_index % 20 != 0 {
            next_address = addresses[last_index as usize + 1].clone();
            break;
        }
    }
    Ok(FetchingState {
        xprv,
        last_index,
        lookup,
        transactions,
        next_address,
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

#[derive(Deserialize)]
struct UtxoResponse {
    address: String,
    unspent: Vec<UnspentOutput>,
}

#[derive(Clone, Deserialize)]
pub struct UnspentOutput {
    pub tx_pos: u32,
    pub tx_hash: String,
    pub value: u64,
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
