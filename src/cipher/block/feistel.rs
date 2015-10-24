use array::{Array, ArrayLength};
use cipher::block::{BlockFn, BlockCipher};
use keyed::Keyed;

use std::mem;
use std::ops::BitXor;

pub struct Feistel<RoundFn, Rounds: ArrayLength<RoundFn>> {
    rounds: Array<RoundFn, Rounds>
}

impl<HalfBlock, RoundFn: BlockFn<Block=HalfBlock>, Rounds: ArrayLength<RoundFn>> BlockFn for Feistel<RoundFn, Rounds> where HalfBlock: Copy + BitXor<HalfBlock, Output=HalfBlock> {
    type Block = (HalfBlock, HalfBlock);

    fn encrypt(&self, block: Self::Block) -> Self::Block {
        let (mut left, mut right) = block;

        for round in self.rounds.iter() {
            left = left ^ round.encrypt(right.clone());
            mem::swap(&mut left, &mut right);
        }

        (right, left)
    }
}

impl<HalfBlock, RoundFn: BlockFn<Block=HalfBlock>, Rounds: ArrayLength<RoundFn>> BlockCipher for Feistel<RoundFn, Rounds> where HalfBlock: Copy + BitXor<HalfBlock, Output=HalfBlock> {
    fn decrypt(&self, block: Self::Block) -> Self::Block {
        let (mut left, mut right) = block;

        for round in self.rounds.iter().rev() {
            left = left ^ round.encrypt(right.clone());
            mem::swap(&mut left, &mut right);
        }

        (right, left)
    }
}

impl<RoundFn: Keyed, Rounds: ArrayLength<RoundFn> + ArrayLength<RoundFn::Key>> Keyed for Feistel<RoundFn, Rounds> {
    type Key = Array<RoundFn::Key, Rounds>;
    fn from_key(key: Self::Key) -> Self {
        Feistel {
            rounds: key.map(RoundFn::from_key)
        }
    }
}
