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

#[repr(C, simd)]
#[derive(Debug, Clone, Copy)]
pub struct u64x2(pub u64, pub u64);

extern {
    pub fn gfmul(a: u64x2, b: u64x2) -> u64x2;
}

pub fn gfmul_simd(a: &[u8], b: &[u8]) -> Vec<u8> {
    let a = &*a as *const _ as *const [u64; 2];
    let b = &*b as *const _ as *const [u64; 2];
    unsafe {
        let a = u64x2((*a)[1].to_be(), (*a)[0].to_be());
        let b = u64x2((*b)[1].to_be(), (*b)[0].to_be());
        let res = gfmul(a, b);
        let result_a = &res as *const _ as *const u64;
        let r = [ (*result_a.offset(1)).to_be(), (*result_a).to_be() ];
        (*(&r as *const _ as *const [u8; 16])).to_vec()
    }
}

#[cfg(test)]
mod test {
    use test::Bencher;

    struct TestCase {
        pub a: Vec<u8>,
        pub b: Vec<u8>,
        pub expected: Vec<u8>
    }

    fn hex_str_to_vec(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        let mut v: Vec<u8> = Vec::new();
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
                b: hex_str_to_vec("0000000000000000a06aea0265e84b8a"),
                expected: hex_str_to_vec("fead2ebe0998a3da7968b8c2f6dfcbd2")
            },
            TestCase {
                a: hex_str_to_vec("0696ce9a49b10a7c21f61cea2d114a22"),
                b: hex_str_to_vec("00000000000000008258e63daab974bc"),
                expected: hex_str_to_vec("89a493638cea727c0bb06f5e9a0248c7")
            },
            TestCase {
                a: hex_str_to_vec("ecf10f64ceff084cd9d9d1349c5d1918"),
                b: hex_str_to_vec("0000000000000000f48a39058af0cf2c"),
                expected: hex_str_to_vec("80490c2d2560fe266a5631670c6729c1"),
            },
            TestCase {
                a: hex_str_to_vec("9c65a83501fae4d5672e54a3e0612727"),
                b: hex_str_to_vec("00000000000000009d8bc634f82dfc78"),
                expected: hex_str_to_vec("d0c221b4819fdd94e7ac8b0edc0ab2cb"),
            },
            TestCase {
                a: hex_str_to_vec("b8885a52910edae3eb16c268e5d3cbc7"),
                b: hex_str_to_vec("000000000000000098878367a0f4f045"),
                expected: hex_str_to_vec("a6f1a7280f1a89436f80fdd5257ec579"),
            },
            TestCase {
                a: hex_str_to_vec("d91376456609fac6f85748784c51b272"),
                b: hex_str_to_vec("0000000000000000f6d1fa7f5e2c73b9"),
                expected: hex_str_to_vec("bcbb318828da56ce0008616226d25e28"),
            },
            TestCase {
                a: hex_str_to_vec("0865625a18a1aace15dba90dedd95d27"),
                b: hex_str_to_vec("0000000000000000395fcb20c3a2a1ff"),
                expected: hex_str_to_vec("a1c704fc6e913666c7bd92e3bc2cbca9"),
            },
            TestCase {
                a: hex_str_to_vec("45ff1a2274ed22d43d31bb224f519fea"),
                b: hex_str_to_vec("0000000000000000d94a263495856bc5"),
                expected: hex_str_to_vec("d0f6ce03966ba1e1face79dfce89e830"),
            },
            TestCase {
                a: hex_str_to_vec("0508aaf2fdeaedb36109e8f830ff2140"),
                b: hex_str_to_vec("0000000000000000c15154674dea15bf"),
                expected: hex_str_to_vec("67e0dbe4ddff54458fa67af764d467dd"),
            },
            TestCase {
                a: hex_str_to_vec("aec8b76366f66dc8e3baaf95020fdfb5"),
                b: hex_str_to_vec("0000000000000000d1552daa9948b824"),
                expected: hex_str_to_vec("0a3c509baed65ac69ec36ae7ad03cc24"),
            },
            TestCase {
                a: hex_str_to_vec("1c2ff5d21b5555781bbd22426912aa58"),
                b: hex_str_to_vec("00000000000000005cdda0b2dafbbf2e"),
                expected: hex_str_to_vec("c9f85163d006bebfc548d010b6590cf2"),
            },
            TestCase {
                a: hex_str_to_vec("1d4db0dfb7b12ea8d431680ac07ba73b"),
                b: hex_str_to_vec("0000000000000000a9913078a5c26c9b"),
                expected: hex_str_to_vec("6e71eaf1e7276f893a9e98a377182211"),
            },
            TestCase {
                a: hex_str_to_vec("f7d946f08e94d545ce583b409322cdf6"),
                b: hex_str_to_vec("000000000000000073c174b844435230"),
                expected: hex_str_to_vec("ad9748630fd502fe9e46f36328d19e8d"),
            },
            TestCase {
                a: hex_str_to_vec("deada9ae22eff9bc3c1669f824c46823"),
                b: hex_str_to_vec("00000000000000006bdd94753484db33"),
                expected: hex_str_to_vec("c40822f2f3984ed58b24bd207b515733"),
            },
            TestCase {
                a: hex_str_to_vec("8146e084b094a0814577558be97f9be1"),
                b: hex_str_to_vec("0000000000000000b3fdd171a771c2ef"),
                expected: hex_str_to_vec("f0093a3df939fe1922c6a848abfdf474"),
            },
            TestCase {
                a: hex_str_to_vec("7c468425a3bda18a842875150b58d753"),
                b: hex_str_to_vec("00000000000000006358fcb8015c9733"),
                expected: hex_str_to_vec("369c44a03648219e2b91f50949efc6b4"),
            },
            TestCase {
                a: hex_str_to_vec("e5f445041c8529d28afad3f8e6b76721"),
                b: hex_str_to_vec("000000000000000006cefb145d7640d1"),
                expected: hex_str_to_vec("8c96b0834c896435fe8d4a70c17a8aff"),
            },
            TestCase {
                a: hex_str_to_vec("a763175a04deea0336d387634525e9b8"),
                b: hex_str_to_vec("00000000000000000000000000000001"),
                expected: hex_str_to_vec("a763175a04deea0336d387634525e9b8"),
            },
            
        ]
    }

    #[test]
    fn simd_test() {
        let test_cases = create_testcases();

        for test_case in &test_cases {
            let result = super::gfmul_simd(&test_case.a, &test_case.b);
            assert_eq!(&result, &test_case.expected);
        }
    }

    #[bench]
    fn simd_test_bench(b: &mut Bencher) {
        let test_case = &create_testcases()[0];
        b.iter(|| {
            super::gfmul_simd(&test_case.a, &test_case.b);
        });
    }
    
}
