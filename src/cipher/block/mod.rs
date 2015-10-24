pub mod feistel;

pub trait BlockFn {
    type Block: Copy;
    fn encrypt(&self, block: Self::Block) -> Self::Block;
}

pub trait BlockCipher: BlockFn {
    fn decrypt(&self, block: Self::Block) -> Self::Block;
}
