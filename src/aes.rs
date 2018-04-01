// Copyright (c) 2006-2009 Graydon Hoare
// Copyright (c) 2009-2013 Mozilla Foundation

// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:

// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
// Source: https://github.com/DaGenix/rust-crypto/blob/master/examples/symmetriccipher.rs#L87

use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer };

const IV: [u8; 16] = [0u8; 16];

pub fn encrypt_block(block: &[u8], key: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize256,
        key,
        &IV,
        blockmodes::NoPadding
    );

    let mut final_result = Vec::<u8>::new();
    let mut buffer = [0; 16];
    let mut read_buffer = buffer::RefReadBuffer::new(block);
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining());
        match result {
            buffer::BufferResult::BufferUnderflow => break,
            buffer::BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

pub fn decrypt_block(block: &[u8], key: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            key,
            &IV,
            blockmodes::NoPadding
    );

    let mut final_result = Vec::<u8>::new();
    let mut buffer = [0; 16];
    let mut read_buffer = buffer::RefReadBuffer::new(block);
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining());
        match result {
            buffer::BufferResult::BufferUnderflow => break,
            buffer::BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}


#[cfg(test)]
mod tests {
    use test::Bencher;

    #[test]
    fn test_encrypt_aes() {
        let key_str = "a0k5lg03mvh2laoqwxcbmtbdksloew58";
        let key_bytes = key_str.as_bytes();

        let plain = [99u8; 16];
        let expected = [0x0b, 0x06, 0xb1, 0x75,
                        0x2c, 0x34, 0x4b, 0x37,
                        0x25, 0xda, 0x61, 0x9f,
                        0x37, 0x35, 0x08, 0x52];
        
        let result = super::encrypt_block(&plain, key_bytes).unwrap();
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_decrypt_aes() {
        let key_str = "a0k5lg03mvh2laoqwxcbmtbdksloew58";
        let key_bytes = key_str.as_bytes();

        let encrypted = [0x0b, 0x06, 0xb1, 0x75,
                        0x2c, 0x34, 0x4b, 0x37,
                        0x25, 0xda, 0x61, 0x9f,
                        0x37, 0x35, 0x08, 0x52];

        let expected = [99u8; 16];

        let result = super::decrypt_block(&encrypted, key_bytes).unwrap();
        assert_eq!(result, expected);
    }

    #[bench]
    fn bench_encrypt_aes(b: &mut Bencher) {
        let key_str = "a0k5lg03mvh2laoqwxcbmtbdksloew58";
        let key_bytes = key_str.as_bytes();

        let plain = [99u8; 16];
        
        b.iter(|| {super::encrypt_block(&plain, key_bytes).unwrap();});
    }

    #[bench]
    fn bench_decrypt_aes(b: &mut Bencher) {
        let key_str = "a0k5lg03mvh2laoqwxcbmtbdksloew58";
        let key_bytes = key_str.as_bytes();

        let encrypted = [0x0b, 0x06, 0xb1, 0x75,
                        0x2c, 0x34, 0x4b, 0x37,
                        0x25, 0xda, 0x61, 0x9f,
                        0x37, 0x35, 0x08, 0x52];


        b.iter(|| { super::decrypt_block(&encrypted, key_bytes).unwrap(); });
    }
}



