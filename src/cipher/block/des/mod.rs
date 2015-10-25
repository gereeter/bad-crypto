use cipher::block::{BlockFn, BlockCipher};
use cipher::block::feistel::Feistel;
use keyed::Keyed;
use secret::Secret;

use signs::{ToSigned, ToUnsigned};
use truncate::Truncate;
use wrapping::WrappingSub;
use array::Array;

use typenum::consts::U16;

mod tables;

struct DesRound {
    // The top 16 bits are 0
    key: Secret<u64>
}

impl BlockFn for DesRound {
    type Block = Secret<u32>;
    fn encrypt(&self, block: Secret<u32>) -> Secret<u32> {
        permute(substitute(expand(block) ^ self.key))
    }
}

impl Keyed for DesRound {
    type Key = Secret<u64>;
    fn from_key(key: Secret<u64>) -> DesRound {
        DesRound {
            key: key
        }
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

impl Keyed for Des {
    type Key = Secret<u64>;
    fn from_key(key: Secret<u64>) -> Des {
        // TODO: check parity bits

        Des {
            inner: Keyed::from_key(key_schedule(key))
        }
    }
}

fn key_schedule(key: Secret<u64>) -> Array<Secret<u64>, U16> {
    let mut left = run_permutation(&tables::PERMUTED_CHOICE_1[0], key, 64, 28);
    let mut right = run_permutation(&tables::PERMUTED_CHOICE_1[1], key, 64, 28);

    let mut ret = Array::from_fn(|_| Secret::new(0));

    for (&rotation, slot) in tables::KEY_SCHEDULE_ROTATIONS.iter().zip(ret.iter_mut()) {
        // NB: 28-bit rotation
        left = left >> (28 - rotation) | (left << rotation) & 0x0FFF_FFFF;
        right = right >> (28 - rotation) | (right << rotation) & 0x0FFF_FFFF;

        let subkey = run_permutation(&tables::PERMUTED_CHOICE_2, left << 28 | right, 56, 48);
        *slot = subkey;
    }

    ret
}

fn split_block(block: Secret<u64>) -> (Secret<u32>, Secret<u32>) {
    ((block >> 32).truncate(), block.truncate())
}

fn join_block(parts: (Secret<u32>, Secret<u32>)) -> Secret<u64> {
    Secret::<u64>::from(parts.0) << 32 | Secret::<u64>::from(parts.1)
}

fn run_permutation(perm: &[u8], val: Secret<u64>, insize: u32, outsize: u32) -> Secret<u64> {
    let mut out = Secret::new(0);
    for (i, &src) in perm.iter().enumerate() {
        let bit = (val >> (insize - src as u32)) & 1;
        out |= bit << (outsize - 1 - i as u32);
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
    run_permutation(&tables::INITIAL_PERMUTATION, block, 64, 64)
}

// Inverse of initial_permute
fn final_permute(block: Secret<u64>) -> Secret<u64> {
    run_permutation(&tables::FINAL_PERMUTATION, block, 64, 64)
}

// Returns 48 bits
fn expand(half_block: Secret<u32>) -> Secret<u64> {
    run_permutation(&tables::EXPANSION_PERMUTATION, Secret::<u64>::from(half_block), 32, 48)
}

// Takes 48 bits
fn substitute(block: Secret<u64>) -> Secret<u32> {
    let mut out = Secret::new(0);
    for i in 0..8 {
        let chunk = ((block >> i*6) & 0x3F).truncate();
        let res = run_substitution(&tables::SUBSTITUTIONS[7 - i as usize], chunk);
        out |= Secret::<u32>::from(res) << i*4;
    }
    out
}

fn permute(block: Secret<u32>) -> Secret<u32> {
    run_permutation(&tables::ROUND_PERMUTATION, Secret::<u64>::from(block), 32, 32).truncate()
}

#[cfg(test)]
mod tests {
    use super::{Des, initial_permute, final_permute, run_substitution, key_schedule, expand, substitute, permute};

    use cipher::block::{BlockFn, BlockCipher};
    use keyed::Keyed;
    use secret::Secret;

    #[test]
    fn initial_final_inverses() {
        for i in 0..64 {
            let val = 1 << i;
            assert_eq!(final_permute(initial_permute(Secret::new(val))).expose(), val);
            assert_eq!(initial_permute(final_permute(Secret::new(val))).expose(), val);
        }
    }

    #[test]
    fn run_substitution_works() {
        let subs = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        for &i in subs.iter() {
            assert_eq!(run_substitution(&subs, Secret::new(i)).expose(), i);
        }
    }

    #[test]
    fn key_schedule_example() {
        let schedule = key_schedule(Secret::new(0x133457799BBCDFF1));
        let correct_keys = [
             0b000110_110000_001011_101111_111111_000111_000001_110010,
             0b011110_011010_111011_011001_110110_111100_100111_100101,
             0b010101_011111_110010_001010_010000_101100_111110_011001,
             0b011100_101010_110111_010110_110110_110011_010100_011101,
             0b011111_001110_110000_000111_111010_110101_001110_101000,
             0b011000_111010_010100_111110_010100_000111_101100_101111,
             0b111011_001000_010010_110111_111101_100001_100010_111100,
             0b111101_111000_101000_111010_110000_010011_101111_111011,
             0b111000_001101_101111_101011_111011_011110_011110_000001,
             0b101100_011111_001101_000111_101110_100100_011001_001111,
             0b001000_010101_111111_010011_110111_101101_001110_000110,
             0b011101_010111_000111_110101_100101_000110_011111_101001,
             0b100101_111100_010111_010001_111110_101011_101001_000001,
             0b010111_110100_001110_110111_111100_101110_011100_111010,
             0b101111_111001_000110_001101_001111_010011_111100_001010,
             0b110010_110011_110110_001011_000011_100001_011111_110101
        ];
        for (subkey, &correct) in schedule.iter().zip(correct_keys.iter()) {
            assert_eq!(subkey.expose(), correct);
        }
    }

    #[test]
    fn initial_example() {
        assert_eq!(initial_permute(Secret::new(0x0123456789ABCDEF)).expose(), 0xCC00CCFFF0AAF0AA);
    }

    #[test]
    fn expand_example() {
        assert_eq!(expand(Secret::new(0xF0AAF0AA)).expose(), 0x7A15557A1555);
    }

    #[test]
    fn substitute_example() {
        assert_eq!(substitute(Secret::new(0x6117BA866527)).expose(), 0x5C82B597);
    }

    #[test]
    fn permute_example() {
        assert_eq!(permute(Secret::new(0x5C82B597)).expose(), 0x234AA9BB);
    }

    #[test]
    fn example1() {
        let des = Des::from_key(Secret::new(0x133457799BBCDFF1));
        assert_eq!(des.encrypt(Secret::new(0x0123456789ABCDEF)).expose(), 0x85E813540F0AB405);
    }

    #[test]
    fn example2() {
        let des = Des::from_key(Secret::new(0x0E329232EA6D0D73));
        assert_eq!(des.encrypt(Secret::new(0x8787878787878787)).expose(), 0);
        assert_eq!(des.decrypt(Secret::new(0)).expose(), 0x8787878787878787);
    }
}
