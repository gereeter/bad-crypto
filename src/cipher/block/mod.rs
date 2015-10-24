pub mod feistel;
pub mod des;

pub trait BlockFn {
    type Block: Clone;
    fn encrypt(&self, block: Self::Block) -> Self::Block;
}

pub trait BlockCipher: BlockFn {
    fn decrypt(&self, block: Self::Block) -> Self::Block;
}
