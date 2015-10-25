use cipher::block::{BlockFn, BlockCipher};
use cipher::block::feistel::Feistel;
use keyed::Keyed;
use secret::Secret;

use rotate::RotateLeft;
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

        let mut left = run_permutation(&tables::PERMUTED_CHOICE_1[0], key);
        let mut right = run_permutation(&tables::PERMUTED_CHOICE_1[1], key);

        let mut key_schedule = Array::from_fn(|_| Secret::new(0));

        for (&rotation, slot) in tables::KEY_SCHEDULE_ROTATIONS.iter().zip(key_schedule.iter_mut()) {
            left = left.rotate_left(rotation);
            right = right.rotate_left(rotation);

            let subkey = run_permutation(&tables::PERMUTED_CHOICE_2, left | right << 28);
            *slot = subkey;

            left = subkey & 0x0FFF_FFFF;
            right = subkey >> 28;
        }

        Des {
            inner: Keyed::from_key(key_schedule)
        }
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
        out |= ((val >> (src as u32 - 1)) & 1) << i as u32;
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
        out |= Secret::<u32>::from(run_substitution(&tables::SUBSTITUTIONS[i as usize], chunk)) << i*4;
    }
    out
}

fn permute(block: Secret<u32>) -> Secret<u32> {
    run_permutation(&tables::ROUND_PERMUTATION, Secret::<u64>::from(block)).truncate()
}

#[cfg(test)]
mod tests {
    use super::{Des, initial_permute, final_permute};

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
    fn example_works() {
        let des = Des::from_key(Secret::new(0x0E329232EA6D0D73));
        assert_eq!(des.encrypt(Secret::new(0x8787878787878787)).expose(), 0);
        assert_eq!(des.decrypt(Secret::new(0)).expose(), 0x8787878787878787);
    }
}
