use cipher::block::{BlockFn, BlockCipher};
use cipher::block::feistel::Feistel;
use secret::Secret;
use truncate::Truncate;

use typenum::consts::U16;

struct SubKey {
    // The top 16 bits are 0
    key: Secret<u64>
}

struct DesRound {
    key: SubKey
}

impl BlockFn for DesRound {
    type Block = Secret<u32>;
    fn encrypt(&self, block: Secret<u32>) -> Secret<u32> {
        permute(substitute(expand(block) ^ self.key.key))
    }
}

pub struct Des {
    inner: Feistel<DesRound, U16>
}

impl BlockFn for Des {
    type Block = Secret<u64>;
    fn encrypt(&self, block: Secret<u64>) -> Secret<u64> {
        final_permute(self.inner.encrypt(initial_permute(block)))
    }
}

impl BlockCipher for Des {
    fn decrypt(&self, block: Secret<u64>) -> Secret<u64> {
        final_permute(self.inner.decrypt(initial_permute(block)))
    }
}

fn run_permutation(perm: &[u8], val: Secret<u64>) -> Secret<u64> {
    let mut out = Secret::new(0);
    for (i, src) in perm.iter().enumerate() {
        out |= ((val >> *src as usize) & 1) << i;
    }
    out
}

// See FIPS Publication 46-3, Appendix 1
const INITIAL_PERMUTATION: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
];

// Inverse of final_permute
fn initial_permute(block: Secret<u64>) -> (Secret<u32>, Secret<u32>) {
    let ret = run_permutation(&INITIAL_PERMUTATION, block);
    (ret.truncate(), (ret >> 32).truncate())
}

// See FIPS Publication 46-3, Appendix 1
const FINAL_PERMUTATION: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9,  49, 17, 57, 25
];

// Inverse of initial_permute
fn final_permute(block: (Secret<u32>, Secret<u32>)) -> Secret<u64> {
    let joined = Secret::<u64>::from(block.0) | (Secret::<u64>::from(block.1) << 32);
    run_permutation(&FINAL_PERMUTATION, joined)
}


// See FIPS Publication 46-3, Appendix 1
const EXPANSION_PERMUTATION: [u8; 48] = [
	32, 1,  2,  3,  4,  5,
	4,  5,  6,  7,  8,  9,
	8,  9,  10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1
];

// Returns 48 bits
fn expand(half_block: Secret<u32>) -> Secret<u64> {
    run_permutation(&EXPANSION_PERMUTATION, Secret::<u64>::from(half_block))
}

// Takes 48 bits
fn substitute(block: Secret<u64>) -> Secret<u32> {
    unimplemented!()
}


// See FIPS Publication 46-3, Appendix 1
const ROUND_PERMUTATION: [u8; 32] = [
	16, 7,  20, 21, 29, 12, 28, 17,
	1,  15, 23, 26, 5,  18, 31, 10,
	2,  8,  24, 14, 32, 27, 3,  9,
	19, 13, 30, 6,  22, 11, 4,  25
];

fn permute(block: Secret<u32>) -> Secret<u32> {
    run_permutation(&ROUND_PERMUTATION, Secret::<u64>::from(block)).truncate()
}
