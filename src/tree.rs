//! Tooling to build merkle trees.

use std::mem;

use rand;

use crate::timestamp::{Timestamp, TimestampBuilder};
use crate::op::HashOp;

#[derive(Debug, Clone)]
pub struct MerkleTreeBuilder {
    tip: [u8; 32],
    items: Vec<TimestampBuilder>,
}

fn build_merkle_tree(items: &mut [TimestampBuilder]) -> [u8; 32] {
    assert!(items.len() > 0);

    if items.len() == 1 {
        if items[0].msg().len() != 32 {
            let t = mem::replace(&mut items[0], TimestampBuilder::new(Box::from([])))
                        .hash(HashOp::Sha256);
            items[0] = t;
        }
        items[0].result().as_ref().try_into().expect("32 byte digest")
    } else {
        let (left, right) = items.split_at_mut(items.len() / 2);
        let (left_tip, right_tip) = (build_merkle_tree(left), build_merkle_tree(right));

        for left_stamp in left {
            let l = mem::take(left_stamp);
            let l = l.append(&right_tip[..])
                     .hash(HashOp::Sha256);

            *left_stamp = l;
        }

        for right_stamp in right {
            let r = mem::take(right_stamp);
            let r = r.prepend(&left_tip[..])
                     .hash(HashOp::Sha256);

            *right_stamp = r;
        }

        let tip = items.first().unwrap().result().try_into().expect("32 byte digest");
        assert_eq!(tip, items.last().unwrap().result());
        tip
    }
}

impl MerkleTreeBuilder {
    pub fn new(mut items: Vec<TimestampBuilder>) -> Self {
        let tip = build_merkle_tree(&mut items[..]);
        Self { items, tip }
    }

    /// Creates a new `MerkleTreeBuilder`, adding a 128-bit nonce to every item.
    pub fn with_nonces(items: impl IntoIterator<Item = TimestampBuilder>) -> Self {
        let items = items.into_iter().map(|item| {
            let nonce: [u8; 16] = rand::random();
            item.append(&nonce[..])
                .hash(HashOp::Sha256)
        }).collect();
        Self::new(items)
    }

    pub fn tip(&self) -> &[u8; 32] {
        &self.tip
    }

    pub fn finish(self, tip_timestamp: Timestamp) -> Vec<Timestamp> {
        assert_eq!(self.items.first().unwrap().result(), tip_timestamp.msg().as_ref());

        /*
        self.items.into_iter()
                  .map(|ts| ts.finish(tip_timestamp.clone()))
                  .collect()
        */ todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic]
    fn test_panics_on_zero_items() {
        MerkleTreeBuilder::new(vec![]);
    }

    #[test]
    fn test_merkle_tree_builder() {
        let mut v = vec![];
        for i in 0 .. 4 {
            v.push(TimestampBuilder::new(vec![i; 32].into()))
        }
        let builder = MerkleTreeBuilder::new(v);
        assert_eq!(builder.tip, [211, 95, 81, 105, 147, 137, 218, 126, 236, 124, 229, 235, 2, 100, 12, 109, 49, 140, 245, 26, 227, 158, 202, 137, 11, 188, 123, 132, 236, 181, 218, 104]);

        let mut v = vec![];
        for i in 0 ..= 255 {
            v.push(TimestampBuilder::new(vec![i; 32].into()))
        }
        let builder = MerkleTreeBuilder::new(v);
        assert_eq!(builder.tip, [252, 172, 191, 66, 234, 208, 21, 52, 228, 232, 243, 175, 181, 101, 38, 122, 15, 81, 143, 16, 87, 98, 223, 146, 109, 9, 25, 247, 251, 145, 102, 203]);

        let mut v = vec![];
        for i in 0 ..= 1_000 {
            v.push(TimestampBuilder::new(vec![0; 32].into()))
        }
        let _builder = MerkleTreeBuilder::new(v);
    }
}
