use cipher::block::{BlockFn, BlockCipher};
use cipher::block::feistel::Feistel;
use secret::Secret;
use signs::{ToSigned, ToUnsigned};
use truncate::Truncate;
use wrapping::WrappingSub;

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
        final_permute(join_block(self.inner.encrypt(split_block(initial_permute(block)))))
    }
}

impl BlockCipher for Des {
    fn decrypt(&self, block: Secret<u64>) -> Secret<u64> {
        final_permute(join_block(self.inner.decrypt(split_block(initial_permute(block)))))
    }
}

fn split_block(block: Secret<u64>) -> (Secret<u32>, Secret<u32>) {
    (block.truncate(), (block >> 32).truncate())
}

fn join_block(parts: (Secret<u32>, Secret<u32>)) -> Secret<u64> {
    Secret::<u64>::from(parts.0) | (Secret::<u64>::from(parts.1) << 32)
}

fn run_permutation(perm: &[u8], val: Secret<u64>) -> Secret<u64> {
    let mut out = Secret::new(0);
    for (i, &src) in perm.iter().enumerate() {
        out |= ((val >> (src as usize - 1)) & 1) << i;
    }
    out
}

// S-boxes are really annoying, as indexing is not a constant time operation. We scan through the whole array masking all elements except for the one we want.
// We assume that all input values are at most 7 bits long.
fn run_substitution(subs: &[u8], val: Secret<u8>) -> Secret<u8> {
    let mut out = Secret::new(0u8);
    for (i, &sub) in subs.iter().enumerate() {
        let correct = val ^ i as u8;
        // To find the mask, we first subtract 1, then extend the sign bit through the whole word.
        // Since `correct` must have its sign bit cleared, the only way for the result to be all ones is if `correct` is 0.
        let mask = (correct.wrapping_sub(1).to_signed() >> 7).to_unsigned();
        out |= mask & sub;
    }
    out
}

// Inverse of final_permute
fn initial_permute(block: Secret<u64>) -> Secret<u64> {
    run_permutation(&tables::INITIAL_PERMUTATION, block)
}

// Inverse of initial_permute
fn final_permute(block: Secret<u64>) -> Secret<u64> {
    run_permutation(&tables::FINAL_PERMUTATION, block)
}

// Returns 48 bits
fn expand(half_block: Secret<u32>) -> Secret<u64> {
    run_permutation(&tables::EXPANSION_PERMUTATION, Secret::<u64>::from(half_block))
}

// Takes 48 bits
fn substitute(block: Secret<u64>) -> Secret<u32> {
    let mut out = Secret::new(0);
    for i in 0..8 {
        let chunk = ((block >> i*6) & 0x3F).truncate();
        out |= Secret::<u32>::from(run_substitution(&tables::SUBSTITUTIONS[i], chunk)) << i*4;
    }
    out
}

fn permute(block: Secret<u32>) -> Secret<u32> {
    run_permutation(&tables::ROUND_PERMUTATION, Secret::<u64>::from(block)).truncate()
}

// See FIPS Publication 46-3, Appendix 1
mod tables {
    pub const INITIAL_PERMUTATION: [u8; 64] = [
	    58, 50, 42, 34, 26, 18, 10, 2,
	    60, 52, 44, 36, 28, 20, 12, 4,
	    62, 54, 46, 38, 30, 22, 14, 6,
	    64, 56, 48, 40, 32, 24, 16, 8,
	    57, 49, 41, 33, 25, 17, 9,  1,
	    59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ];

    pub const FINAL_PERMUTATION: [u8; 64] = [
       40, 8, 48, 16, 56, 24, 64, 32,
       39, 7, 47, 15, 55, 23, 63, 31,
       38, 6, 46, 14, 54, 22, 62, 30,
       37, 5, 45, 13, 53, 21, 61, 29,
       36, 4, 44, 12, 52, 20, 60, 28,
       35, 3, 43, 11, 51, 19, 59, 27,
       34, 2, 42, 10, 50, 18, 58, 26,
       33, 1, 41, 9,  49, 17, 57, 25
    ];

    pub const EXPANSION_PERMUTATION: [u8; 48] = [
        32, 1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9,  10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ];

    pub const ROUND_PERMUTATION: [u8; 32] = [
        16, 7,  20, 21, 29, 12, 28, 17,
        1,  15, 23, 26, 5,  18, 31, 10,
        2,  8,  24, 14, 32, 27, 3,  9,
        19, 13, 30, 6,  22, 11, 4,  25
    ];

    // NB: These are in lexicographic order, not the outer-bit major order given in the spec.
    pub const SUBSTITUTIONS: [[u8; 64]; 8] = [
        [
            14, 0,
            4,  15,
            13, 7,
            1,  4,
            2,  14,
            15, 2,
            11, 13,
            8,  1,
            3,  10,
            10, 6,
            6,  12,
            12, 11,
            5,  9,
            9,  5,
            0,  3,
            7,  8,

            4,  15,
            1,  12,
            14, 8,
            8,  2,
            13, 4,
            6,  9,
            2,  1,
            11, 7,
            15, 5,
            12, 11,
            9,  3,
            7,  14,
            3,  10,
            10, 0,
            5,  6,
            0,  13,
        ],
        [
            15, 3,
            1, 13,
            8, 4,
            14, 7,
            6, 15,
            11, 2,
            3, 8,
            4, 14,
            9, 12,
            7, 0,
            2, 1,
            13, 10,
            12, 6,
            0, 9,
            5, 11,
            10, 5,

            0, 13,
            14, 8,
            7, 10,
            11, 1,
            10, 3,
            4, 15,
            13, 4,
            1, 2,
            5, 11,
            8, 6,
            12, 7,
            6, 12,
            9, 0,
            3, 5,
            2, 14,
            15, 9,
        ],
        [
            10, 13,
            0, 7,
            9, 0,
            14, 9,
            6, 3,
            3, 4,
            15, 6,
            5, 10,
            1, 2,
            13, 8,
            12, 5,
            7, 14,
            11, 12,
            4, 11,
            2, 15,
            8, 1,

            13, 1,
            6, 10,
            4, 13,
            9, 0,
            8, 6,
            15, 9,
            3, 8,
            0, 7,
            11, 4,
            1, 15,
            2, 14,
            12, 3,
            5, 11,
            10, 5,
            14, 2,
            7, 12,
        ],
        [
            7, 13,
            13, 8,
            14, 11,
            3, 9,
            0, 3,
            6, 4,
            9, 6,
            10, 10,
            1, 2,
            2, 8,
            8, 5,
            5, 14,
            11, 12,
            12, 11,
            4, 15,
            15, 1,

            10, 3,
            6, 15,
            9, 0,
            9, 6,
            8, 10,
            15, 1,
            3, 13,
            0, 8,
            11, 9,
            1, 4,
            2, 5,
            12, 11,
            5, 12,
            10, 7,
            14, 2,
            7, 14,
        ],
        [
            2, 14,
            12, 11,
            4, 2,
            1, 9,
            7, 3,
            10, 4,
            11, 6,
            6, 10,
            8, 2,
            5, 8,
            3, 5,
            15, 14,
            13, 12,
            0, 11,
            14, 15,
            9, 1,

            4, 11,
            2, 8,
            1, 12,
            9, 7,
            8, 1,
            15, 14,
            3, 2,
            0, 13,
            11, 6,
            1, 15,
            2, 0,
            12, 9,
            5, 10,
            10, 4,
            14, 5,
            7, 3,
        ],
        [
            12, 10,
            1, 15,
            10, 4,
            15, 9,
            9, 3,
            2, 4,
            6, 6,
            8, 10,
            0, 2,
            13, 8,
            3, 5,
            4, 14,
            14, 12,
            7, 11,
            5, 15,
            11, 1,

            9, 4,
            14, 3,
            15, 2,
            9, 12,
            8, 9,
            15, 5,
            3, 15,
            0, 10,
            11, 11,
            1, 14,
            2, 1,
            12, 7,
            5, 6,
            10, 0,
            14, 8,
            7, 13,

        ],
        [
            4, 13,
            11, 0,
            2, 11,
            14, 9,
            15, 3,
            0, 4,
            8, 6,
            13, 10,
            3, 2,
            12, 8,
            9, 5,
            7, 14,
            5, 12,
            10, 11,
            6, 15,
            1, 1,

            1, 6,
            4, 11,
            11, 13,
            9, 8,
            8, 1,
            15, 4,
            3, 10,
            0, 7,
            11, 9,
            1, 5,
            2, 0,
            12, 15,
            5, 14,
            10, 2,
            14, 3,
            7, 12,
        ],
        [
            13, 1,
            2, 15,
            8, 13,
            4, 9,
            6, 3,
            15, 4,
            11, 6,
            1, 10,
            10, 2,
            9, 8,
            3, 5,
            14, 14,
            5, 12,
            0, 11,
            12, 15,
            7, 1,

            7, 2,
            11, 1,
            4, 14,
            9, 7,
            8, 4,
            15, 10,
            3, 8,
            0, 13,
            11, 15,
            1, 12,
            2, 9,
            12, 0,
            5, 3,
            10, 5,
            14, 6,
            7, 11,
        ]
    ];
}

#[cfg(test)]
mod tests {
    use super::{initial_permute, final_permute};

    use secret::Secret;

    #[test]
    fn initial_final_inverses() {
        for i in 0..64 {
            let val = 1 << i;
            assert_eq!(final_permute(initial_permute(Secret::new(val))).expose(), val);
            assert_eq!(initial_permute(final_permute(Secret::new(val))).expose(), val);
        }
    }
}
