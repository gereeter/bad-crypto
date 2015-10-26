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

#[inline(always)]
fn do_swap(block: &mut Secret<u64>, location: u64, offset: u32) {
    let temp = ((*block << offset) ^ *block) & location;
    *block ^= temp;
    *block ^= temp >> offset;
}

// Inverse of final_permute
//
// # Optimization
//
// The process of calculating the initial permutation can be substantially optimized
// from a straightforward bit-by-bit process. The first observation to make is that
// since `initial_permute` is invertible, it can be broken down into a series of swaps.
// Due to the xor-swaps, these can be done cheaply and with many bits at once.
//
// The second observation is that the permutation itself is very structured. We need to
// send
//
//     1  2  3  4  5  6  7  8      58 50 42 34 26 10 2
//     9  10 11 12 13 14 15 16     60 52 44 36 28 12 4
//     17 18 19 20 21 22 23 24     62 54 46 38 30 14 6
//     25 26 27 28 29 30 31 32  -\ 64 56 48 40 32 16 8
//     33 34 35 36 37 38 39 40  -/ 57 49 41 33 25 9  1
//     41 42 43 44 45 46 47 48     59 51 43 35 27 11 3
//     49 50 51 52 53 54 55 56     61 53 45 37 29 13 5
//     57 58 59 60 61 62 63 64     63 55 47 39 31 15 7
//
// From straightforward visual inspection, this can be broken down into reflecting the
// block of bits across this upper right-lower left diagonal and permuting the resulting
// rows. Reflection can be done as a series of swaps by doing multiple "block-level" reflections:
//
//   do_swap(&mut block, 0xF0F0F0F000000000, 36)
//     1  2  3  4  5  6  7  8      37 38 39 40 5  6  7  8
//     9  10 11 12 13 14 15 16     45 46 47 48 13 14 15 16
//     17 18 19 20 21 22 23 24     53 54 55 56 21 22 23 24
//     25 26 27 28 29 30 31 32  -\ 61 62 63 64 29 30 31 32
//     33 34 35 36 37 38 39 40  -/ 33 34 35 36 1  2  3  4
//     41 42 43 44 45 46 47 48     41 42 43 44 9  10 11 12
//     49 50 51 52 53 54 55 56     49 50 51 52 17 18 19 20
//     57 58 59 60 61 62 63 64     57 58 59 60 25 26 27 28
//
//   do_swap(&mut block, 0xCCCC0000CCCC0000, 18)
//     37 38 39 40 5  6  7  8      55 56 39 40 23 24 7  8
//     45 46 47 48 13 14 15 16     63 64 47 48 31 32 15 16
//     53 54 55 56 21 22 23 24     53 54 37 38 21 22 5  6
//     61 62 63 64 29 30 31 32  -\ 61 62 45 46 29 30 13 14
//     33 34 35 36 1  2  3  4   -/ 51 52 35 36 19 20 3  4
//     41 42 43 44 9  10 11 12     59 60 43 44 27 28 11 12
//     49 50 51 52 17 18 19 20     49 50 33 34 17 18 1  2
//     57 58 59 60 25 26 27 28     57 58 41 42 25 26 9  10
//
// At this point, we would finish the reflection with
//
//   do_swap(&mut block, 0xAA00AA00AA00AA00, 9);
//     55 56 39 40 23 24 7  8      64 56 48 40 32 24 16 8
//     63 64 47 48 31 32 15 16     63 55 47 39 31 23 15 7
//     53 54 37 38 21 22 5  6      62 54 46 38 30 22 14 6
//     61 62 45 46 29 30 13 14  -\ 61 53 45 37 29 21 13 5
//     51 52 35 36 19 20 3  4   -/ 60 52 44 36 28 20 12 4
//     59 60 43 44 27 28 11 12     59 51 43 35 27 19 11 3
//     49 50 51 52 17 18 1  2      58 50 42 34 26 18 10 2
//     57 58 59 60 25 26 9  10     57 49 41 33 25 17 9  1
//
// However, the intermediate structure after two swaps has much of the structure
// that we want to do the final row permute - notice that the odd numbers that
// need to be separated from the evens are already in two separate columns. All we
// need to do is reverse the order:
//
//   do_swap(&mut block, 0xFF000000FF000000, 24);
//     55 56 39 40 23 24 7  8      61 62 45 46 29 30 13 14
//     63 64 47 48 31 32 15 16     63 64 47 48 31 32 15 16
//     53 54 37 38 21 22 5  6      53 54 37 38 21 22 5  6
//     61 62 45 46 29 30 13 14  -\ 55 56 39 40 23 24 7  8
//     51 52 35 36 19 20 3  4   -/ 57 58 41 42 25 26 9  10
//     59 60 43 44 27 28 11 12     59 60 43 44 27 28 11 12
//     49 50 33 34 17 18 1  2      49 50 33 34 17 18 1  2
//     57 58 41 42 25 26 9  10     51 52 35 36 19 20 3  4
//
//   do_swap(&mut block, 0xFFFF000000000000, 48);
//     61 62 45 46 29 30 13 14     49 50 33 34 17 18 1  2
//     63 64 47 48 31 32 15 16     51 52 35 36 19 20 3  4
//     53 54 37 38 21 22 5  6      53 54 37 38 21 22 5  6
//     55 56 39 40 23 24 7  8   -\ 55 56 39 40 23 24 7  8
//     57 58 41 42 25 26 9  10  -/ 57 58 41 42 25 26 9  10
//     59 60 43 44 27 28 11 12     59 60 43 44 27 28 11 12
//     49 50 33 34 17 18 1  2      61 62 45 46 29 30 13 14
//     51 52 35 36 19 20 3  4      63 64 47 48 31 32 15 16
//
// At this point, we are almost done: the odd numbers that are still on top need to be
// put onto the bottom.
//
//   do_swap(&mut block, 0xAAAAAAAA00000000, 33);
//     49 50 33 34 17 18 1  2      58 50 42 34 26 10 2
//     51 52 35 36 19 20 3  4      60 52 44 36 28 12 4
//     53 54 37 38 21 22 5  6      62 54 46 38 30 14 6
//     55 56 39 40 23 24 7  8   -\ 64 56 48 40 32 16 8
//     57 58 41 42 25 26 9  10  -/ 57 49 41 33 25 9  1
//     59 60 43 44 27 28 11 12     59 51 43 35 27 11 3
//     61 62 45 46 29 30 13 14     61 53 45 37 29 13 5
//     63 64 47 48 31 32 15 16     63 55 47 39 31 15 7
//
// This completes the permutation.
//
// TODO: look at 32 bit performance
fn initial_permute(mut block: Secret<u64>) -> Secret<u64> {
    do_swap(&mut block, 0xF0F0F0F000000000, 36);
    do_swap(&mut block, 0xCCCC0000CCCC0000, 18);
    do_swap(&mut block, 0xFF000000FF000000, 24);
    do_swap(&mut block, 0xFFFF000000000000, 48);
    do_swap(&mut block, 0xAAAAAAAA00000000, 33);

    block
}

// Inverse of initial_permute
fn final_permute(mut block: Secret<u64>) -> Secret<u64> {
    // Since a swap is its own inverse, we just do the swaps of initial_permute backwards
    do_swap(&mut block, 0xAAAAAAAA00000000, 33);
    do_swap(&mut block, 0xFFFF000000000000, 48);
    do_swap(&mut block, 0xFF000000FF000000, 24);
    do_swap(&mut block, 0xCCCC0000CCCC0000, 18);
    do_swap(&mut block, 0xF0F0F0F000000000, 36);
    block
}

// Returns 48 bits
//
// # Optimization
//
// For the most part, the expansion permutation copies contiguous 6-bit chunks of bits from
// the input to the output. We do this directly.
fn expand(half_block: Secret<u32>) -> Secret<u64> {
    let half_block = Secret::<u64>::from(half_block);

    (half_block & 1) << 47 | (half_block & 0x80000000) >> 31
        | (half_block & 0xF8000000) << 15
        | (half_block & 0x1F800000) << 13
        | (half_block & 0x01F80000) << 11
        | (half_block & 0x001F8000) << 9
        | (half_block & 0x0001F800) << 7
        | (half_block & 0x00001F80) << 5
        | (half_block & 0x000001F8) << 3
        | (half_block & 0x0000001F) << 1
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
    extern crate test;
    extern crate rand;

    use super::{Des, key_schedule, initial_permute, final_permute, expand, substitute, permute};
    use super::{run_permutation, run_substitution};
    use super::tables;

    use cipher::block::{BlockFn, BlockCipher};
    use keyed::Keyed;
    use secret::Secret;

    use self::test::Bencher;
    use self::rand::{Rng, thread_rng};

    #[test]
    fn initial_final_inverses() {
        for i in 0..64 {
            let val = 1 << i;
            assert_eq!(final_permute(initial_permute(Secret::new(val))).expose(), val);
            assert_eq!(initial_permute(final_permute(Secret::new(val))).expose(), val);
        }
    }

    #[test]
    fn initial_matches_spec_rand() {
        let mut rng = thread_rng();
        for _ in 0..10000 {
            let val = rng.gen();
            assert_eq!(initial_permute(Secret::new(val)).expose(), run_permutation(&tables::INITIAL_PERMUTATION, Secret::new(val), 64, 64).expose());
        }
    }

    #[test]
    fn final_matches_spec_rand() {
        let mut rng = thread_rng();
        for _ in 0..10000 {
            let val = rng.gen();
            assert_eq!(final_permute(Secret::new(val)).expose(), run_permutation(&tables::FINAL_PERMUTATION, Secret::new(val), 64, 64).expose());
        }
    }

    #[test]
    fn expand_matches_spec_rand() {
        let mut rng = thread_rng();
        for _ in 0..10000 {
            let val = rng.gen();
            assert_eq!(expand(Secret::new(val)).expose(), run_permutation(&tables::EXPANSION_PERMUTATION, Secret::new(val as u64), 32, 48).expose());
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

    #[bench]
    fn bench_initial_permute(bencher: &mut Bencher) {
        let input = thread_rng().gen();
        bencher.iter(|| {
            initial_permute(Secret::new(test::black_box(input)))
        });
    }

    #[bench]
    fn bench_final_permute(bencher: &mut Bencher) {
        let input = thread_rng().gen();
        bencher.iter(|| {
            final_permute(Secret::new(test::black_box(input)))
        });
    }

    #[bench]
    fn bench_expand(bencher: &mut Bencher) {
        let input = thread_rng().gen();
        bencher.iter(|| {
            expand(Secret::new(test::black_box(input)))
        });
    }

    #[bench]
    fn bench_substitute(bencher: &mut Bencher) {
        let input = thread_rng().gen::<u64>() >> 16;
        bencher.iter(|| {
            substitute(Secret::new(test::black_box(input)))
        });
    }

    #[bench]
    fn bench_permute(bencher: &mut Bencher) {
        let input = thread_rng().gen();
        bencher.iter(|| {
            permute(Secret::new(test::black_box(input)))
        });
    }

    #[bench]
    fn bench_encrypt(bencher: &mut Bencher) {
        let des = Des::from_key(Secret::new(thread_rng().gen()));
        let input = thread_rng().gen();
        bencher.iter(|| {
            des.encrypt(Secret::new(test::black_box(input)))
        });
    }
}
