// Description: Diffie-Hellman key exchange, and HKDF for key derivation

#pragma once // prevent multiple inclusions
#include<gmp.h>

// some convenient macros
#define ISPRIME(x) mpz_probab_prime_p(x, 25) // check if x is prime
#define NEWZ(x) mpz_t x; mpz_init(x) // declare and initialize a new GMP variable

#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf) // convert byte array to GMP variable
#define Z2BYTES(x, buf, len_ptr) mpz_export((buf), (len_ptr), -1, 1, 0, 0, (x)) // convert GMP variable to byte array

extern mpz_t q; // "small" prime; should be 256 bits or larger
extern mpz_t p; // "large" prime; should be 2048 bits or larger, with q dividing p-1 (q = k * (p-1))
extern mpz_t g; // generator; should be generator of the group of order q.
extern size_t qBitlen; // length of q in bits
extern size_t pBitlen; // length of p in bits
extern size_t gBitlen; // length of g in bits
extern size_t qLen; // length of q in bytes
extern size_t pLen; // length of p in bytes

#ifdef __cplusplus 
extern "C" {
#endif // end if C++
// try to read q,p,g from file
int init(const char *filename);
// generate fresh DH parameters q,p,g. This is a slow operation, so it should be done only once.
// so it is best to call this function only once and save the parameters to a file for later use.
int initFromScratch(size_t qBitlen, size_t pBitlen);
//  set secret key sk to a random exponent(this part is secret)
//  set public key pk to g^sk mod p (this part is public)
int dhGen(mpz_t sk, mpz_t pk);
//  given a secret key sk_mine and a public key pk_yours, compute the shared secret diffie Hellman value(sk_mine^pk_yours mod p)
//  apply a KDF(key derivation function) to obtain buflen bytes of key, stored in keybuf
int dhFinal(mpz_t sk_mine, mpz_t pk_mine, mpz_t pk_yours, unsigned char *keybuf, size_t buflen);
//  pk_mine is included just to avoid recomputing it from sk_mine (shared_secret = (g^sk_yours)^sk_own mod p = g^(sk_mine*sk_yours) mod p)
#ifdef __cplusplus 
}
#endif 