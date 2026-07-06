//! Independent reference implementation of ZigChain's consensus-critical
//! primitives, for differential testing against the Zig node.
//!
//! Every byte-exact rule (domain-separated tagged hashing, canonical
//! serialization, txid/wtxid/sighash/address, GHOSTDAG coloring and ordering)
//! is reimplemented here from the specs — NOT ported line-by-line — so that
//! agreement between the two codebases is real evidence of correctness rather
//! than a shared bug. Any divergence is a consensus split waiting to happen.

use std::collections::{HashMap, HashSet};

pub type Hash = [u8; 32];

// --- domain-separated tagged hashing (BLAKE3) ---

pub fn domain_ctx(name: &str) -> &'static str {
    match name {
        "txid" => "zigchain.v1.txid",
        "wtxid" => "zigchain.v1.wtxid",
        "sighash" => "zigchain.v1.sighash",
        "address" => "zigchain.v1.address",
        "merkle_leaf" => "zigchain.v1.merkle.leaf",
        "merkle_node" => "zigchain.v1.merkle.node",
        "block_header" => "zigchain.v1.block.header",
        "witness" => "zigchain.v1.witness",
        "finality_vote" => "zigchain.v1.finality.vote",
        _ => panic!("unknown domain {name}"),
    }
}

/// BIP340-style tagged hash: prime the state with H(tag) twice, then the message.
pub fn tagged(domain: &str, msg: &[u8]) -> Hash {
    let th = blake3::hash(domain_ctx(domain).as_bytes());
    let mut h = blake3::Hasher::new();
    h.update(th.as_bytes());
    h.update(th.as_bytes());
    h.update(msg);
    *h.finalize().as_bytes()
}

/// Deterministic block id for scenarios: idOf(i) = tagged(block_header, u32_le(i)).
pub fn id_of(i: u32) -> Hash {
    tagged("block_header", &i.to_le_bytes())
}

// --- canonical serialization (little-endian, u32 counts, u32-prefixed varbytes) ---

#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn bytes(&mut self, s: &[u8]) {
        self.0.extend_from_slice(s);
    }
    pub fn hash(&mut self, h: &Hash) {
        self.0.extend_from_slice(h);
    }
    pub fn varbytes(&mut self, s: &[u8]) {
        self.u32(s.len() as u32);
        self.bytes(s);
    }
}

// --- primitives ---

pub struct OutPoint {
    pub txid: Hash,
    pub index: u32,
}
pub struct Output {
    pub value: u64,
    pub scheme: u8,
    pub commitment: Hash,
}
pub struct Witness {
    pub scheme: u8,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<OutPoint>,
    pub outputs: Vec<Output>,
    pub witnesses: Vec<Witness>,
    pub payload: Vec<u8>,
}

impl Transaction {
    pub fn encode_body(&self, w: &mut Writer) {
        w.u32(self.version);
        w.u32(self.inputs.len() as u32);
        for i in &self.inputs {
            w.hash(&i.txid);
            w.u32(i.index);
        }
        w.u32(self.outputs.len() as u32);
        for o in &self.outputs {
            w.u64(o.value);
            w.u8(o.scheme);
            w.hash(&o.commitment);
        }
        w.varbytes(&self.payload);
    }

    pub fn encode_witnesses(&self, w: &mut Writer) {
        w.u32(self.witnesses.len() as u32);
        for wi in &self.witnesses {
            w.u8(wi.scheme);
            w.varbytes(&wi.pubkey);
            w.varbytes(&wi.signature);
        }
    }

    pub fn txid(&self) -> Hash {
        let mut w = Writer::default();
        self.encode_body(&mut w);
        tagged("txid", &w.0)
    }

    pub fn wtxid(&self) -> Hash {
        let id = self.txid();
        let mut w = Writer::default();
        w.hash(&id);
        self.encode_witnesses(&mut w);
        tagged("wtxid", &w.0)
    }

    pub fn sighash(&self, scheme: u8) -> Hash {
        let mut w = Writer::default();
        w.u8(scheme);
        self.encode_body(&mut w);
        tagged("sighash", &w.0)
    }
}

pub fn address_commitment(scheme: u8, pubkey: &[u8]) -> Hash {
    let mut msg = vec![scheme];
    msg.extend_from_slice(pubkey);
    tagged("address", &msg)
}

pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return tagged("merkle_leaf", b"");
    }
    let mut level: Vec<Hash> = leaves.iter().map(|l| tagged("merkle_leaf", l)).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let mut m = Vec::with_capacity(64);
                m.extend_from_slice(&level[i]);
                m.extend_from_slice(&level[i + 1]);
                next.push(tagged("merkle_node", &m));
            } else {
                next.push(level[i]); // promote lone node
            }
            i += 2;
        }
        level = next;
    }
    level[0]
}

// --- GHOSTDAG ---

pub struct GhostdagData {
    pub blue_score: u64,
    pub selected_parent: Option<Hash>,
    pub mergeset_blues: Vec<Hash>,
    pub mergeset_reds: Vec<Hash>,
    pub blues: HashMap<Hash, u32>,
}

pub struct Ghostdag {
    pub k: u32,
    parents: HashMap<Hash, Vec<Hash>>,
    pub data: HashMap<Hash, GhostdagData>,
    topo: Vec<Hash>,
    index: HashMap<Hash, usize>,
    past: Vec<HashSet<usize>>,
}

fn less(a: &Hash, b: &Hash) -> bool {
    a < b // lexicographic on [u8;32]
}

impl Ghostdag {
    pub fn new(k: u32, parents: HashMap<Hash, Vec<Hash>>) -> Self {
        Ghostdag {
            k,
            parents,
            data: HashMap::new(),
            topo: Vec::new(),
            index: HashMap::new(),
            past: Vec::new(),
        }
    }

    /// Deterministic topological order: Kahn's algorithm emitting the smallest
    /// ready id first (matching the Zig DAG store exactly).
    fn topo_order(&self) -> Vec<Hash> {
        let mut indeg: HashMap<Hash, usize> = HashMap::new();
        let mut children: HashMap<Hash, Vec<Hash>> = HashMap::new();
        for (id, ps) in &self.parents {
            indeg.insert(*id, ps.len());
            for p in ps {
                children.entry(*p).or_default().push(*id);
            }
        }
        let mut ready: Vec<Hash> = indeg
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(id, _)| *id)
            .collect();
        let mut out = Vec::with_capacity(self.parents.len());
        while !ready.is_empty() {
            let mut min_i = 0;
            for i in 1..ready.len() {
                if less(&ready[i], &ready[min_i]) {
                    min_i = i;
                }
            }
            let id = ready.swap_remove(min_i);
            out.push(id);
            if let Some(kids) = children.get(&id) {
                for c in kids {
                    let d = indeg.get_mut(c).unwrap();
                    *d -= 1;
                    if *d == 0 {
                        ready.push(*c);
                    }
                }
            }
        }
        out
    }

    pub fn compute(&mut self) {
        self.topo = self.topo_order();
        for (i, id) in self.topo.iter().enumerate() {
            self.index.insert(*id, i);
        }
        // Reachability cache: past[i] = ancestor topo-indices of topo[i].
        let n = self.topo.len();
        self.past = vec![HashSet::new(); n];
        for i in 0..n {
            let id = self.topo[i];
            let ps = self.parents.get(&id).cloned().unwrap_or_default();
            let mut set = HashSet::new();
            for p in &ps {
                let pi = self.index[p];
                set.insert(pi);
                let parent_past = self.past[pi].clone();
                set.extend(parent_past);
            }
            self.past[i] = set;
        }
        let order = self.topo.clone();
        for id in order {
            self.compute_block(id);
        }
    }

    fn is_ancestor(&self, a: &Hash, b: &Hash) -> bool {
        let (ia, ib) = (self.index[a], self.index[b]);
        self.past[ib].contains(&ia)
    }

    fn in_anticone(&self, x: &Hash, y: &Hash) -> bool {
        x != y && !self.is_ancestor(x, y) && !self.is_ancestor(y, x)
    }

    fn compute_block(&mut self, id: Hash) {
        let parents = self.parents.get(&id).cloned().unwrap_or_default();
        if parents.is_empty() {
            let mut blues = HashMap::new();
            blues.insert(id, 0);
            self.data.insert(
                id,
                GhostdagData {
                    blue_score: 0,
                    selected_parent: None,
                    mergeset_blues: vec![],
                    mergeset_reds: vec![],
                    blues,
                },
            );
            return;
        }

        // Selected parent: max blue_score, tie -> smaller id.
        let mut sp = parents[0];
        for p in &parents[1..] {
            let s = self.data[p].blue_score;
            let ss = self.data[&sp].blue_score;
            if s > ss || (s == ss && less(p, &sp)) {
                sp = *p;
            }
        }
        let mut blues = self.data[&sp].blues.clone();

        // Mergeset = past(id) \ past(sp) \ {sp}, in topological (ascending) order.
        let ii = self.index[&id];
        let isp = self.index[&sp];
        let mut mergeset = Vec::new();
        for ai in 0..self.topo.len() {
            if !self.past[ii].contains(&ai) {
                continue;
            }
            if ai == isp || self.past[isp].contains(&ai) {
                continue;
            }
            mergeset.push(self.topo[ai]);
        }

        let mut mergeset_blues = Vec::new();
        let mut mergeset_reds = Vec::new();
        for kb in mergeset {
            if self.try_color_blue(&mut blues, &kb) {
                mergeset_blues.push(kb);
            } else {
                mergeset_reds.push(kb);
            }
        }

        blues.insert(id, 0);
        let sp_score = self.data[&sp].blue_score;
        self.data.insert(
            id,
            GhostdagData {
                blue_score: sp_score + 1 + mergeset_blues.len() as u64,
                selected_parent: Some(sp),
                mergeset_blues,
                mergeset_reds,
                blues,
            },
        );
    }

    fn try_color_blue(&self, blues: &mut HashMap<Hash, u32>, kb: &Hash) -> bool {
        let anticone: Vec<Hash> = blues
            .keys()
            .filter(|x| self.in_anticone(x, kb))
            .copied()
            .collect();
        if anticone.len() as u32 > self.k {
            return false;
        }
        if anticone.iter().any(|x| blues[x] == self.k) {
            return false;
        }
        blues.insert(*kb, anticone.len() as u32);
        for x in anticone {
            *blues.get_mut(&x).unwrap() += 1;
        }
        true
    }

    pub fn selected_tip(&self) -> Option<Hash> {
        let mut best: Option<Hash> = None;
        let mut best_score = 0u64;
        for (id, d) in &self.data {
            if best.is_none()
                || d.blue_score > best_score
                || (d.blue_score == best_score && less(id, &best.unwrap()))
            {
                best = Some(*id);
                best_score = d.blue_score;
            }
        }
        best
    }

    pub fn order(&self) -> Vec<Hash> {
        // Tips (no children), ascending id.
        let mut has_child: HashSet<Hash> = HashSet::new();
        for ps in self.parents.values() {
            for p in ps {
                has_child.insert(*p);
            }
        }
        let mut tips: Vec<Hash> = self
            .parents
            .keys()
            .filter(|id| !has_child.contains(*id))
            .copied()
            .collect();
        tips.sort();

        let mut visited: HashSet<Hash> = HashSet::new();
        let mut result = Vec::new();
        for t in tips {
            self.emit(&t, &mut visited, &mut result);
        }
        result
    }

    fn emit(&self, id: &Hash, visited: &mut HashSet<Hash>, result: &mut Vec<Hash>) {
        if visited.contains(id) {
            return;
        }
        let d = &self.data[id];
        if let Some(sp) = d.selected_parent {
            self.emit(&sp, visited, result);
        }
        for b in &d.mergeset_blues {
            self.emit(b, visited, result);
        }
        for r in &d.mergeset_reds {
            self.emit(r, visited, result);
        }
        visited.insert(*id);
        result.push(*id);
    }
}

pub fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

pub fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
