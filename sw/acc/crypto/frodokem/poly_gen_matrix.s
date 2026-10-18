/* Copyright zeroRISC Inc. */
/* Modified by Authors of "Towards ML-KEM & ML-DSA on OpenTitan" (https://eprint.iacr.org/2024/1192). */
/* Copyright "Towards ML-KEM & ML-DSA on OpenTitan" Authors. */
/* Modified by Ruben Niederhagen and Hoang Nguyen Hien Pham - authors of */
/* "Improving ML-KEM & ML-DSA on OpenTitan - Efficient Multiplication Vector Instructions for OTBN" */
/* (https://eprint.iacr.org/2025/2028). */
/* Copyright Ruben Niederhagen and Hoang Nguyen Hien Pham. */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

.text

/* Config to start a SHAKE-128 operation. */
#define SHAKE128_CFG 0x2

/**
 * Initialization of the SHAKE-128 operation for poly_gen_matrix.
 *
 * Configure a SHAKE-128 operation for an 18-byte message and absorb
 * i || seedA, so that a subsequent call to `poly_gen_matrix` can squeeze
 * row i of the matrix A.
 *
 * The message is the row index i (2 bytes, little-endian) followed by
 * seedA (16 bytes). Both are read from one buffer with a single wide load,
 * and only its first 18 bytes are sent (kmac_partial_write = 18).
 *
 * This routine is constant time.
 *
 * @param[in]  x10: dmem pointer to i || seedA (18 bytes, 32-byte aligned)
 *
 * clobbered registers: x5, w0
 * clobbered flag groups: none
 */

.globl poly_gen_matrix_init
.type poly_gen_matrix_init, @function
poly_gen_matrix_init:
  /* Initialize a SHAKE128 operation: message length 18 bytes */
  addi  x5, x0, 18
  slli  x5, x5, 5
  addi  x5, x5, SHAKE128_CFG
  csrrw x0, kmac_cfg, x5

  /* Send the message to the Keccak core. */
  bn.ld   w0, 0(x10)
  li      x5, 18
  csrrw   x0, kmac_partial_write, x5
  bn.wsrw kmac_msg, w0
  ret

/**
 * Generation of one row of the matrix A.
 *
 * Squeeze one row of A (n entries of 16 bits, 2n bytes) from the SHAKE-128
 * operation set up by `poly_gen_matrix_init`. Every 32-byte squeeze holds
 * 16 consecutive entries A[i][16t .. 16t+15], one per 16-bit lane. No
 * rejection or reduction is needed: q is a power of two and the reduction
 * mod q is deferred to packing.
 *
 * On return, x11 has been advanced by one row (2n bytes).
 *
 * This routine is constant time.
 *
 * @param[out] x11: dmem pointer to the output row (32-byte aligned)
 * @param[in]  x12: number of 32-byte squeezes per row, n/16 (40, 61 or 84)
 * @param[in]  kmac_digest: SHAKE-128 squeeze set up by poly_gen_matrix_init
 *
 * clobbered registers: x11, w0
 * clobbered flag groups: none
 */

.globl poly_gen_matrix
.type poly_gen_matrix, @function
poly_gen_matrix:
  loop x12, 2
    bn.wsrr w0, kmac_digest     /* 16 entries of A */
    bn.sd   w0, 0(x11++)        /* store them and advance by 32 bytes */
  endloop
  ret
