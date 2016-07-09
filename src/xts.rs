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
// Original source: http://www.bjrn.se/code/pytruecrypt/xtspy.txt

use gf2n::GF;
use num::{BigUint, One};

fn gf2pow128powof2(n: u32, gf: &GF) -> BigUint {
    let nn = n;
    let two = BigUint::from_bytes_be(&[2u8]);
    if nn < 128 {
        super::num::checked_pow(two, nn as usize).expect("Pow of BigUint failed!")
    } else {
        let mut val: BigUint = One::one();
        for _ in 0..nn {
            val = gf.gf2pow128mul(val.clone(), &two);
        }
        val
    }
}

pub fn xts_decrypt(key1: &[u8], key2: &[u8], i: u8, block: &[u8]) -> [u8; 16] {
    let gf: GF = GF::new();
    
    let n_txt = [0u8; 16];
    let e_k2_n = super::aes::encrypt_block(&n_txt, key2).expect("Encrypting block failed!");

    let a_i = gf2pow128powof2(i as u32, &gf);

    let mut e_mul_a = gf.gf2pow128mul(BigUint::from_bytes_be(&e_k2_n), &a_i).to_bytes_be();

    if e_mul_a.len() < 16 {
        e_mul_a = arr_size_to_16b(e_mul_a);
    }

    let xored = xor_bytes_16(&e_mul_a, block);

    let mut key1_decrypted = super::aes::decrypt_block(&xored, key1)
        .expect("Decrypting block failed!");

    if key1_decrypted.len() < 16 {
        key1_decrypted = arr_size_to_16b(key1_decrypted);
    }

    xor_bytes_16(&e_mul_a, &key1_decrypted)
}

fn xor_bytes_16(a: &[u8], b: &[u8]) -> [u8; 16] {
    assert!(a.len() == 16 && b.len() == 16, "xor_bytes_16: length != 16");
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = &a[i] ^ &b[i];
    }
    result
}

fn arr_size_to_16b(arr: Vec<u8>) -> Vec<u8> {
    let mut temp = vec![0u8; 16];
    let diff = 16 - arr.len();
    for (i, item) in arr.iter().enumerate() {
        temp[i+diff] = *item;
    }
    temp
}
