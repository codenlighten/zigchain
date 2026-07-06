//! Reads the shared scenarios file (path as argv[1], or stdin) and prints a
//! canonical report of computed values. The Zig `vectors` tool prints the exact
//! same report for the same input; `tools/difftest.sh` diffs the two.

use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;
use zigchain_ref::*;

#[derive(Deserialize)]
struct Scenarios {
    #[serde(default)]
    tx_vectors: Vec<TxV>,
    #[serde(default)]
    address_vectors: Vec<AddrV>,
    #[serde(default)]
    merkle_vectors: Vec<MerkleV>,
    #[serde(default)]
    dag_scenarios: Vec<DagV>,
}

#[derive(Deserialize)]
struct TxV {
    version: u32,
    #[serde(default)]
    inputs: Vec<InV>,
    #[serde(default)]
    outputs: Vec<OutV>,
    #[serde(default)]
    witnesses: Vec<WitV>,
    #[serde(default)]
    payload: String,
    sighash_scheme: u8,
}
#[derive(Deserialize)]
struct InV {
    txid: String,
    index: u32,
}
#[derive(Deserialize)]
struct OutV {
    value: u64,
    scheme: u8,
    commitment: String,
}
#[derive(Deserialize)]
struct WitV {
    scheme: u8,
    pubkey: String,
    signature: String,
}
#[derive(Deserialize)]
struct AddrV {
    scheme: u8,
    pubkey: String,
}
#[derive(Deserialize)]
struct MerkleV {
    leaves: Vec<String>,
}
#[derive(Deserialize)]
struct DagV {
    name: String,
    k: u32,
    blocks: Vec<BlockV>,
}
#[derive(Deserialize)]
struct BlockV {
    id: u32,
    parents: Vec<u32>,
}

fn h32(s: &str) -> Hash {
    let v = from_hex(s);
    assert_eq!(v.len(), 32, "expected 32-byte hex, got {}", s);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn main() {
    let mut input = String::new();
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        input = std::fs::read_to_string(&args[1]).unwrap();
    } else {
        std::io::stdin().read_to_string(&mut input).unwrap();
    }
    let s: Scenarios = serde_json::from_str(&input).unwrap();

    for (i, tv) in s.tx_vectors.iter().enumerate() {
        let tx = Transaction {
            version: tv.version,
            inputs: tv
                .inputs
                .iter()
                .map(|x| OutPoint {
                    txid: h32(&x.txid),
                    index: x.index,
                })
                .collect(),
            outputs: tv
                .outputs
                .iter()
                .map(|x| Output {
                    value: x.value,
                    scheme: x.scheme,
                    commitment: h32(&x.commitment),
                })
                .collect(),
            witnesses: tv
                .witnesses
                .iter()
                .map(|x| Witness {
                    scheme: x.scheme,
                    pubkey: from_hex(&x.pubkey),
                    signature: from_hex(&x.signature),
                })
                .collect(),
            payload: from_hex(&tv.payload),
        };
        println!("tx {i} txid {}", to_hex(&tx.txid()));
        println!("tx {i} wtxid {}", to_hex(&tx.wtxid()));
        println!("tx {i} sighash {}", to_hex(&tx.sighash(tv.sighash_scheme)));
    }

    for (i, av) in s.address_vectors.iter().enumerate() {
        let c = address_commitment(av.scheme, &from_hex(&av.pubkey));
        println!("addr {i} {}", to_hex(&c));
    }

    for (i, mv) in s.merkle_vectors.iter().enumerate() {
        let leaves: Vec<Hash> = mv.leaves.iter().map(|l| h32(l)).collect();
        println!("merkle {i} {}", to_hex(&merkle_root(&leaves)));
    }

    for dv in &s.dag_scenarios {
        let mut parents: HashMap<Hash, Vec<Hash>> = HashMap::new();
        let mut id_to_int: HashMap<Hash, u32> = HashMap::new();
        for b in &dv.blocks {
            let id = id_of(b.id);
            id_to_int.insert(id, b.id);
            parents.insert(id, b.parents.iter().map(|p| id_of(*p)).collect());
        }
        let mut gd = Ghostdag::new(dv.k, parents);
        gd.compute();

        let mut ids: Vec<&BlockV> = dv.blocks.iter().collect();
        ids.sort_by_key(|b| b.id);
        for b in ids {
            let d = &gd.data[&id_of(b.id)];
            println!("dag {} blue {}:{}", dv.name, b.id, d.blue_score);
        }
        let tip = gd.selected_tip().unwrap();
        println!("dag {} tip {}", dv.name, id_to_int[&tip]);
        let order: Vec<String> = gd
            .order()
            .iter()
            .map(|h| id_to_int[h].to_string())
            .collect();
        println!("dag {} order {}", dv.name, order.join(","));
    }
}
