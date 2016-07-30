// Original work Copyright (c) 2008 Bjorn Edstrom <be@bjrn.se>
// Modified work Copyright 2016 Semih Helvaci

// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,

// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// Original source: http://www.bjrn.se/code/pytruecrypt/gf2npy.txt

use num::{BigUint, Zero, One};

#[repr(C, simd)]
#[derive(Debug, Clone, Copy)]
pub struct u64x2(pub u64, pub u64);

extern {
    pub fn gfmul(a: u64x2, b: u64x2) -> u64x2;
}

pub struct GF {
    // 0x1 00000000 00000000 00000000 00000087
    mod128: BigUint
}

impl GF {
    pub fn new() -> GF {
        GF {
            mod128: {
                BigUint::from_bytes_be(
                    &[0x1, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00,
                      0x87])
            }
        }
    }

    fn xor_mod(&self, mut n: BigUint, modval: &BigUint) -> BigUint {
        loop {
            let n_bits = n.bits() - 1;
            let modval_bits = modval.bits() - 1;

            if n_bits == modval_bits { n = n ^ modval; }
            if n_bits <= modval_bits { break; }

            let x = n_bits - modval_bits;
            
            let lower = &n & ((BigUint::one() << x) - BigUint::one());
            n = (((n >> x) ^ modval) << x) | lower;
        }
        n
    }

    fn gf2n_mul(&self, mut a: BigUint, b: &BigUint, modval: &BigUint) -> BigUint {
        let mut res: BigUint = BigUint::zero();
        let mut a_cnt = 0;

        while !a.is_zero() {
            let mut b2 = b.clone();
            let mut b_cnt = 0;

            if !(&a & BigUint::one()).is_zero() {
                while !b2.is_zero() {
                    if !(&b2 & BigUint::one()).is_zero() {
                        res = res ^ (BigUint::one() << (a_cnt + b_cnt));
                    }
                    b2 = b2 >> 1;
                    b_cnt += 1;
                }
            }

            a = a >> 1;
            a_cnt += 1;
        }

        self.xor_mod(res, modval)
    }

    pub fn gf2pow128mul(&self, a: BigUint, b: &BigUint) -> BigUint {
        self.gf2n_mul(a, b, &self.mod128)
    }
}


pub fn gfmul_simd(a: &[u8], b: &[u8]) -> Vec<u8> {
    let a = &*a as *const _ as *const [u64; 2];
    let b = &*b as *const _ as *const [u64; 2];
    unsafe {
        let a = u64x2((*a)[1].to_be(), (*a)[0].to_be());
        let b = u64x2((*b)[0].to_be(), (*b)[1].to_be());
        let result_a = &gfmul(a, b) as *const _ as *const u64;
        let r = [ (*result_a.offset(1)).to_be(), (*result_a).to_be() ];
        (*(&r as *const _ as *const [u8; 16])).to_vec()
    }
}

#[cfg(test)]
mod test {
    use test::Bencher;
    
    use num::BigUint;
    use gf2n::GF;


    struct TestCase {
        pub a: Vec<u8>,
        pub b: Vec<u8>,
        pub expected: Vec<u8>
    }

    fn hex_str_to_vec(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        let mut v: Vec<u8> = Vec::with_capacity(16);
        let mut i = 0;
        while i < s.len() {
            v.push(u8::from_str_radix(&s[i..i+2], 16).unwrap());
            i += 2;
        }
        v
    }

    fn create_testcases() -> Vec<TestCase> {
        vec![
            TestCase {
                a: hex_str_to_vec("b9623d587488039f1486b2d8d9283453"),
                b: hex_str_to_vec("a06aea0265e84b8a"),
                expected: hex_str_to_vec("fead2ebe0998a3da7968b8c2f6dfcbd2")
            },
            TestCase {
                a: hex_str_to_vec("0696ce9a49b10a7c21f61cea2d114a22"),
                b: hex_str_to_vec("8258e63daab974bc"),
                expected: hex_str_to_vec("89a493638cea727c0bb06f5e9a0248c7")
            },
            TestCase {
                a: hex_str_to_vec("ecf10f64ceff084cd9d9d1349c5d1918"),
                b: hex_str_to_vec("f48a39058af0cf2c"),
                expected: hex_str_to_vec("80490c2d2560fe266a5631670c6729c1"),
            },
            TestCase {
                a: hex_str_to_vec("9c65a83501fae4d5672e54a3e0612727"),
                b: hex_str_to_vec("9d8bc634f82dfc78"),
                expected: hex_str_to_vec("d0c221b4819fdd94e7ac8b0edc0ab2cb"),
            },
            TestCase {
                a: hex_str_to_vec("b8885a52910edae3eb16c268e5d3cbc7"),
                b: hex_str_to_vec("98878367a0f4f045"),
                expected: hex_str_to_vec("a6f1a7280f1a89436f80fdd5257ec579"),
            },
            TestCase {
                a: hex_str_to_vec("d91376456609fac6f85748784c51b272"),
                b: hex_str_to_vec("f6d1fa7f5e2c73b9"),
                expected: hex_str_to_vec("bcbb318828da56ce0008616226d25e28"),
            },
            TestCase {
                a: hex_str_to_vec("0865625a18a1aace15dba90dedd95d27"),
                b: hex_str_to_vec("395fcb20c3a2a1ff"),
                expected: hex_str_to_vec("a1c704fc6e913666c7bd92e3bc2cbca9"),
            },
            TestCase {
                a: hex_str_to_vec("45ff1a2274ed22d43d31bb224f519fea"),
                b: hex_str_to_vec("d94a263495856bc5"),
                expected: hex_str_to_vec("d0f6ce03966ba1e1face79dfce89e830"),
            },
            TestCase {
                a: hex_str_to_vec("0508aaf2fdeaedb36109e8f830ff2140"),
                b: hex_str_to_vec("c15154674dea15bf"),
                expected: hex_str_to_vec("67e0dbe4ddff54458fa67af764d467dd"),
            },
            TestCase {
                a: hex_str_to_vec("aec8b76366f66dc8e3baaf95020fdfb5"),
                b: hex_str_to_vec("d1552daa9948b824"),
                expected: hex_str_to_vec("0a3c509baed65ac69ec36ae7ad03cc24"),
            },
            TestCase {
                a: hex_str_to_vec("1c2ff5d21b5555781bbd22426912aa58"),
                b: hex_str_to_vec("5cdda0b2dafbbf2e"),
                expected: hex_str_to_vec("c9f85163d006bebfc548d010b6590cf2"),
            },
            TestCase {
                a: hex_str_to_vec("1d4db0dfb7b12ea8d431680ac07ba73b"),
                b: hex_str_to_vec("a9913078a5c26c9b"),
                expected: hex_str_to_vec("6e71eaf1e7276f893a9e98a377182211"),
            },
            TestCase {
                a: hex_str_to_vec("f7d946f08e94d545ce583b409322cdf6"),
                b: hex_str_to_vec("73c174b844435230"),
                expected: hex_str_to_vec("ad9748630fd502fe9e46f36328d19e8d"),
            },
            TestCase {
                a: hex_str_to_vec("deada9ae22eff9bc3c1669f824c46823"),
                b: hex_str_to_vec("6bdd94753484db33"),
                expected: hex_str_to_vec("c40822f2f3984ed58b24bd207b515733"),
            },
            TestCase {
                a: hex_str_to_vec("8146e084b094a0814577558be97f9be1"),
                b: hex_str_to_vec("b3fdd171a771c2ef"),
                expected: hex_str_to_vec("f0093a3df939fe1922c6a848abfdf474"),
            },
            TestCase {
                a: hex_str_to_vec("7c468425a3bda18a842875150b58d753"),
                b: hex_str_to_vec("6358fcb8015c9733"),
                expected: hex_str_to_vec("369c44a03648219e2b91f50949efc6b4"),
            },
            TestCase {
                a: hex_str_to_vec("e5f445041c8529d28afad3f8e6b76721"),
                b: hex_str_to_vec("06cefb145d7640d1"),
                expected: hex_str_to_vec("8c96b0834c896435fe8d4a70c17a8aff"),
            },
        ]
    }

    #[test]
    fn gf2_128_mul_test() {
        let test_cases = create_testcases();
        
        let gf = GF::new();

        for test_case in test_cases {
            let result = gf.gf2pow128mul(
                BigUint::from_bytes_be(&test_case.a),
                &BigUint::from_bytes_be(&test_case.b)
            );
            let expected = BigUint::from_bytes_be(&test_case.expected);
            
            assert!(result == expected);
        }
    }

    #[test]
    fn simd_test() {
        let test_cases = create_testcases();

        for test_case in test_cases {
            let result = super::gfmul_simd(&test_case.a, &test_case.b);
            assert!(&result == &test_case.expected);
        }
    }

    #[bench]
    fn simd_test_bench(b: &mut Bencher) {
        let test_case = &create_testcases()[0];
        b.iter(|| {
            super::gfmul_simd(&test_case.a, &test_case.b);
        });
    }
    
    #[bench]
    fn gf2_128_mul_bench(b: &mut Bencher) {
        let gf = GF::new();
        let test_case = &create_testcases()[0];
        b.iter(|| {
            gf.gf2pow128mul(
                BigUint::from_bytes_be(&test_case.a),
                &BigUint::from_bytes_be(&test_case.b)
            );
        });
    }
    
}
