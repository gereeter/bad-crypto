use array::{Array, ArrayLength};
use cipher::block::{BlockFn, BlockCipher};

use std::mem;
use std::ops::BitXor;

pub struct Feistel<Rounds: ArrayLength<RoundFn>, RoundFn: BlockFn> {
    rounds: Array<RoundFn, Rounds>
}

impl<HalfBlock, RoundFn: BlockFn<Block=HalfBlock>, Rounds: ArrayLength<RoundFn>> BlockFn for Feistel<Rounds, RoundFn> where HalfBlock: Copy + BitXor<HalfBlock, Output=HalfBlock> {
    type Block = (HalfBlock, HalfBlock);

    fn encrypt(&self, block: Self::Block) -> Self::Block {
        let (mut left, mut right) = block;

        for round in self.rounds.iter() {
            left = left ^ round.encrypt(right);
            mem::swap(&mut left, &mut right);
        }

        (right, left)
    }
}

impl<HalfBlock, RoundFn: BlockFn<Block=HalfBlock>, Rounds: ArrayLength<RoundFn>> BlockCipher for Feistel<Rounds, RoundFn> where HalfBlock: Copy + BitXor<HalfBlock, Output=HalfBlock> {
    fn decrypt(&self, block: Self::Block) -> Self::Block {
        let (mut left, mut right) = block;

        for round in self.rounds.iter().rev() {
            left = left ^ round.encrypt(right);
            mem::swap(&mut left, &mut right);
        }

        (right, left)
    }
}
