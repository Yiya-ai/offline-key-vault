import { weierstrass } from '@noble/curves/abstract/weierstrass.js';
import { bytesToHex, hexToBytes } from '@noble/curves/utils.js';
import forge from 'node-forge';

// SM2 domain parameters (GB/T 32918.5), also published in OpenSSL ec_curve.c.
// Only key derivation / point validation use this curve; no custom signing code.
const SM2 = weierstrass({
  p: 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffffn,
  a: 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffcn,
  b: 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93n,
  n: 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123n,
  Gx: 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7n,
  Gy: 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0n,
  h: 1n,
});

export function sm2Public(secretHex) {
  const bytes = hexToBytes(secretHex);
  try {
    if (bytes.length !== 32) throw new Error('Invalid SM2 scalar');
    const n = SM2.Fn.fromBytes(bytes);
    if (n === 0n) throw new Error('Invalid SM2 scalar');
    return bytesToHex(SM2.BASE.multiply(n).toBytes(false));
  } finally { bytes.fill(0); }
}
export function sm2Validate(publicHex) {
  const point = SM2.fromBytes(hexToBytes(publicHex));
  point.assertValidity();
  if (point.equals(SM2.ZERO)) throw new Error('Invalid SM2 point');
  return bytesToHex(point.toBytes(false));
}
export function pkcs12Kdf(password, saltHex, purpose, rounds, length, hash) {
  if (typeof password !== 'string' || password.length > 1024 || password.includes('\0') ||
      !Number.isInteger(rounds) || rounds < 1 || rounds > 2000000 ||
      ![1, 2, 3].includes(purpose) || !Number.isInteger(length) || length < 1 || length > 64 ||
      !['sha1', 'sha256', 'sha384', 'sha512'].includes(hash) || !/^(?:[0-9a-f]{2}){1,1024}$/.test(saltHex)) {
    throw new Error('Invalid bounded PKCS12 KDF parameters');
  }
  return forge.pbe.generatePkcs12Key(password, forge.util.createBuffer(forge.util.hexToBytes(saltHex)),
    purpose, rounds, length, forge.md[hash].create()).toHex();
}
