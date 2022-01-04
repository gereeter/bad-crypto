use std::ops::{BitAnd, BitXor, Shl};
use utils::traits::rotate::{RotateRight};

struct Blocks<T> {
    b0:  T, b1:  T, b2:  T, b3:  T,
    b4:  T, b5:  T, b6:  T, b7:  T,
    b8:  T, b9:  T, b10: T, b11: T,
    b12: T, b13: T, b14: T, b15: T,
}

const ROTATIONS_32: [u32; 4] = [8, 11, 16, 31];
const ROTATIONS_64: [u32; 4] = [8, 19, 40, 63];

#[inline(always)]
fn h_add<T>(lhs: T, rhs: T) -> T
        where T: Copy + BitAnd<T, Output=T> + BitXor<T, Output=T> + Shl<u32, Output=T> {
    (lhs ^ rhs) ^ ((lhs & rhs) << 1)
}

#[inline]
fn g_scramble<T>(blocks: [&mut T; 4], rotations: [u32; 4])
        where T: Copy + BitAnd<T, Output=T> + BitXor<T, Output=T> + Shl<u32, Output=T> + RotateRight<u32, Output=T> {
    *blocks[0] = h_add(*blocks[0], *blocks[1]);
    *blocks[3] = (*blocks[0] ^ *blocks[3]).rotate_right(rotations[0]);
    *blocks[2] = h_add(*blocks[2], *blocks[3]);
    *blocks[1] = (*blocks[1] ^ *blocks[2]).rotate_right(rotations[1]);
    *blocks[0] = h_add(*blocks[0], *blocks[1]);
    *blocks[3] = (*blocks[0] ^ *blocks[3]).rotate_right(rotations[2]);
    *blocks[2] = h_add(*blocks[2], *blocks[3]);
    *blocks[1] = (*blocks[1] ^ *blocks[2]).rotate_right(rotations[3]);
}

fn f_square_scramble<T>(blocks: &mut Blocks<T>, rotations: [u32; 4])
        where T: Copy + BitAnd<T, Output=T> + BitXor<T, Output=T> + Shl<u32, Output=T> + RotateRight<u32, Output=T> {
    // Columns
    g_scramble([&mut blocks.b0, &mut blocks.b4, &mut blocks.b8,  &mut blocks.b12], rotations);
    g_scramble([&mut blocks.b1, &mut blocks.b5, &mut blocks.b9,  &mut blocks.b13], rotations);
    g_scramble([&mut blocks.b2, &mut blocks.b6, &mut blocks.b10, &mut blocks.b14], rotations);
    g_scramble([&mut blocks.b3, &mut blocks.b7, &mut blocks.b11, &mut blocks.b15], rotations);

    // Diagonals
    g_scramble([&mut blocks.b0, &mut blocks.b5, &mut blocks.b10, &mut blocks.b15], rotations);
    g_scramble([&mut blocks.b1, &mut blocks.b6, &mut blocks.b11, &mut blocks.b12], rotations);
    g_scramble([&mut blocks.b2, &mut blocks.b7, &mut blocks.b8,  &mut blocks.b13], rotations);
    g_scramble([&mut blocks.b3, &mut blocks.b4, &mut blocks.b0,  &mut blocks.b14], rotations);
}

#[cfg(test)]
mod test {
    extern crate test;

    use super::{Blocks, ROTATIONS_32, ROTATIONS_64, f_square_scramble};

    use self::test::Bencher;

    #[bench]
    fn bench_f_32(bencher: &mut Bencher) {
        let mut state: Blocks<u32> = Blocks {
            b0:   0, b1:   1, b2:   2, b3:   3,
            b4:   4, b5:   5, b6:   6, b7:   7,
            b8:   8, b9:   9, b10: 10, b11: 11,
            b12: 12, b13: 13, b14: 14, b15: 15,
        };
        bencher.iter(|| {
            f_square_scramble(&mut state, ROTATIONS_32);
        });
    }

    #[bench]
    fn bench_f_64(bencher: &mut Bencher) {
        let mut state: Blocks<u64> = Blocks {
            b0:   0, b1:   1, b2:   2, b3:   3,
            b4:   4, b5:   5, b6:   6, b7:   7,
            b8:   8, b9:   9, b10: 10, b11: 11,
            b12: 12, b13: 13, b14: 14, b15: 15,
        };
        bencher.iter(|| {
            f_square_scramble(&mut state, ROTATIONS_64);
        });
    }
}
