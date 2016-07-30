#include <stdio.h>
#include <wmmintrin.h>

typedef unsigned long long u64;

// https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf
// Application of the method for reduction modulo x^128 + x^7 + x^2 + x + 1.
__m128i reduce(u64 X0, u64 X1, u64 X2, u64 X3) {
  u64 A = X3 >> 63;
  u64 B = X3 >> 62;
  u64 C = X3 >> 57;

  u64 D = X2^A^B^C;

  __m128i TEMP;
  TEMP[0] = D;
  TEMP[1] = X3;


  __m128i E;
  E[0] = TEMP[0] << 1;
  E[1] = (TEMP[1] << 1) | (TEMP[0] >> 63);
  
  __m128i F;
  F[0] = TEMP[0] << 2;
  F[1] = (TEMP[1] << 2) | (TEMP[0] >> 62);

  __m128i G;
  G[0] = TEMP[0] << 7;
  G[1] = (TEMP[1] << 7) | (TEMP[0] >> 57);

  __m128i result;
  result[0] = X0^(D^E[0]^F[0]^G[0]);
  result[1] = X1^(X3^E[1]^F[1]^G[1]);
  return result;
}

// https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf
// Performing Carry-less Multiplication of 128-bit Operands Using PCLMULQDQ. Algorithm 2.
__m128i gfmul(__m128i a, __m128i b) {
  __m128i am;
  __m128i bm;
  am[0] = a[0]^a[1];
  am[1] = 0;

  bm[0] = b[0]^b[1];
  bm[1] = 0;
  
  __m128i C = _mm_clmulepi64_si128 (a, b, 0b10001);
  __m128i D = _mm_clmulepi64_si128 (a, b, 0);
  __m128i E = _mm_clmulepi64_si128 (am, bm, 0);

  u64 X3 = C[1];
  u64 X2 = C[0]^C[1]^D[1]^E[1];
  u64 X1 = D[1]^C[0]^D[0]^E[0];
  u64 X0 = D[0];

  return reduce(X0, X1, X2, X3);
}

__m128i give_me_back(__m128i a) {
  printf("%02llx %02llx\n", a[0], a[1]);
  return a;
}
