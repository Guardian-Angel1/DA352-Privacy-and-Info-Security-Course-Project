// Description: Diffie-Hellman key exchange, and HKDF for key derivation
#include<stdio.h>
#include<gmp.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/evp.h>
#include<openssl/sha.h>
#include<openssl/hmac.h>
#include<winsock2.h>
#include<bcrypt.h>
#include<windows.h>
#include <stdint.h>
#include "diffie-hellman.h"

#pragma comment(lib, "bcrypt.lib")

uint64_t htobe64(uint64_t host_64bits) {
    return ((host_64bits & 0x00000000000000FFULL) << 56) |
        ((host_64bits & 0x000000000000FF00ULL) << 40) |
        ((host_64bits & 0x0000000000FF0000ULL) << 24) |
        ((host_64bits & 0x00000000FF000000ULL) << 8)  |
        ((host_64bits & 0x000000FF00000000ULL) >> 8)  |
        ((host_64bits & 0x0000FF0000000000ULL) >> 24) |
        ((host_64bits & 0x00FF000000000000ULL) >> 40) |
        ((host_64bits & 0xFF00000000000000ULL) >> 56);
}




mpz_t q; // "small" prime; should be 256 bits or larger
mpz_t p; // "large" prime; should be 2048 bits or larger, with q dividing p-1 (q = k * (p-1))
mpz_t g; // generator; should be generator of the group of order q.

size_t qBitlen; // length of q in bits
size_t pBitlen; // length of p in bits
size_t qLen; // length of q in bytes
size_t pLen; // length of p in bytes

// this constant is arbitrary and does need to be a secret
// this is used in the HKDF function to derive the key from the shared secret
const char * hmacsalt = "z3Dow}^Z]8Uu5>pr#;{QUs!133";

int init(const char* filename){
    mpz_init(q);
    mpz_init(p);
    mpz_init(g);    
    FILE* f = fopen(filename, "rb");
    if (f == NULL) {
        fprintf(stderr, "Error opening file parameters \n");
        return -1;
    }
    // read q,p,g from file
    // p is a 4096 bit prime, and g generates a subgroup of order q, which is a 512 bit prime.
    // g is a generator of the group of order q
    int nvalues = gmp_fscanf(f, "q = %Zd\np = %Zd\ng = %Zd\n", q, p, g);
    fclose(f);

    if (nvalues != 3) {
        fprintf(stderr, "Error reading parameters from file \n");
        return -1;
    }

    // check if q,p,g are prime
    if(ISPRIME(q) == 0){
        fprintf(stderr, "q is not prime \n");
        return -1;
    }
    if(ISPRIME(p) == 0){
        fprintf(stderr, "p is not prime \n");
        return -1;
    }

    // making sure that q divides p-1
    NEWZ(t);
    NEWZ(r);
    mpz_sub_ui(r,p,1); // r = p-1
    if(mpz_divisible_p(r,q) == 0){
        fprintf(stderr, "q does not divide p-1 \n");
        return -1;
    }
    mpz_divexact(t,r,q); // t = (p-1)/q
    if(mpz_divisible_p(t,q)){
        fprintf(stderr, "q^2 does not divide p-1 \n");
        return -1;
    }
    // check if g is a generator of the group of order q
    mpz_powm(r,g,t,p); // if r != 1 then g is not a generator of the group of order q since q is prime
    if(mpz_cmp_ui(r,1) == 0){
        fprintf(stderr, "g is not a generator of the group of order q \n");
        return -1;
    }

    qBitlen = mpz_sizeinbase(q, 2); // length of q in bits
    pBitlen = mpz_sizeinbase(p, 2); // length of p in bits

    qLen = qBitlen/8 + (qBitlen%8 != 0); // length of q in bytes
    pLen = pBitlen/8 + (pBitlen%8 != 0); // length of p in bytes

    return 0;
}
// this function is used to generate a random number of the right number of bits
// it uses the BCryptGenRandom function from the Windows API
void secure_random_bytes(unsigned char* buffer, size_t length) {
    NTSTATUS status = BCryptGenRandom(
        NULL,
        buffer,
        (ULONG)length,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Secure RNG failed.\n");
        exit(1);
    }
}
int initFromScratch(size_t qbits, size_t pbits){
    // select random prime p of the right number of bits, then multiply by
    // a random even integer, add 1, and check if it is prime.
    // If so, then we have found q and p respectively.

    qBitlen = qbits;
    pBitlen = pbits;
    qLen = qBitlen/8 + (qBitlen%8 != 0); // length of q in bytes
    pLen = pBitlen/8 + (pBitlen%8 != 0); // length of p in bytes
    size_t rLen = pLen - qLen; // length of r in bytes
    unsigned char *qCand = malloc(qLen); // candidate for q
    unsigned char *rCand = malloc(rLen); // candidate for r
    mpz_init(q);
    mpz_init(p);
    mpz_init(g);
    NEWZ(r); // r = (p-1)/q
    NEWZ(t); // scratch space
    
    do{
        do{
            secure_random_bytes(qCand, qLen);
            BYTES2Z(q,qCand,qLen);
        } while (ISPRIME(q) == 0);
        // now trying to get p
        secure_random_bytes(rCand,rLen);
        rCand[0] &= 0xfe; // set least significant bit to 0 (make r even)
        BYTES2Z(r,rCand,rLen);
        mpz_mul(p,q,r); // p =q*r
        mpz_add_ui(p,p,1); // p=p+1
        // should make sure q^2 doesn't divide p-1
        // suffices to check if q divides r
        mpz_mod(t,r,q); //t = r%q
        // now check if t is 0
        if (mpz_cmp_ui(t,0)==0) continue;
    } while(ISPRIME(p) == 0);
    gmp_printf("q = %Zd\np = %Zd\n",q,p);
    // now find a generator of the subgroup of order q;
    //  Turns out just about anything to the r power will work
    size_t tLen = qLen;
    unsigned char* tCand = malloc(tLen);
    do {
        secure_random_bytes(tCand, tLen);
        BYTES2Z(t,tCand,tLen);
        if (mpz_cmp_ui(t,0)==0) continue;
        mpz_powm(g,t,r,p); // efficiently do g = t^r % p
    } while(mpz_cmp_ui(g,1) == 0); // since q is prime, any such g/=1 

    gmp_printf("g = %Zd\n",g);
	return 0;

}

// choose random exponent sk and compute g^sk mod p
//  init or intFromScratch must be called first
int dhGen(mpz_t sk, mpz_t pk){
    size_t bufLen = qLen + 32; // read extra to get closer to uniform distribution
    unsigned char* buf = malloc(bufLen);
    secure_random_bytes(buf, bufLen); // fill with random bytes
    NEWZ(a);
    BYTES2Z(a,buf,qLen); // convert to integer
    mpz_mod(sk,a,q); // sk = a % q
    mpz_powm(pk,g,sk,p); // pk = g^sk mod p
    return 0;
}

int dhFinal(mpz_t sk_mine, mpz_t pk_mine, mpz_t pk_yours, unsigned char *keybuf, size_t buflen){
    NEWZ(x);
    mpz_powm(x,pk_yours,sk_mine,p); // x = pk_yours^sk_mine mod p
    // now apply key derivation function to get desired number of bytes
    // we use the diffie hellman value as the key and the salt as the hmac key
    unsigned char* SK = malloc(pLen);
    memset(SK,0,pLen); // make sure SK is all zeros
    size_t nWritten; // number of bytes written
    Z2BYTES(x, SK, &nWritten);
    const size_t maclen = 64; // output len of sha512
    unsigned char PRK[maclen];
    memset(PRK,0,maclen); // make sure PRK is all zeros
    HMAC(EVP_sha512(), hmacsalt, strlen(hmacsalt), SK, nWritten, PRK, 0); // PRK = HMAC(SK)
    /* Henceforth, use PRK as the HMAC key.  The initial chunk of derived key
	 * is computed as HMAC_{PRK}(CTX || 0), where CTX = pk_A || pk_B, where
	 * (pk_A,pk_B) is {pk_mine,pk_yours}, sorted ascending.
	 * To generate further chunks K(i+1), proceed as follows:
	 * K(i+1) = HMAC_{PRK}(K(i) || CTX || i). */
	/* For convenience (?) we'll use a buffer named CTX that will contain
	 * the previous key as well as the index i:
	 *         +------------------------+
	 *  CTX == | K(i) | PK_A | PK_B | i |
	 *         +------------------------+
	 * */
    const size_t ctxlen = maclen +2*pLen + 8; // length of context
    // the extra 8 bytes are to concatenate the key chunk with the index
    unsigned char* CTX = malloc(ctxlen); // context buffer
    uint64_t index = 0;
    uint64_t indexBE = index;
    memset(CTX, 0 , ctxlen); // make sure CTX is all zeros
    if (mpz_cmp(pk_mine, pk_yours) < 0) {
        Z2BYTES(pk_mine, CTX + maclen, &nWritten);             // copy pk_mine
        Z2BYTES(pk_yours, CTX + maclen + pLen, &nWritten);     // copy pk_yours
    } else {
        Z2BYTES(pk_yours, CTX + maclen, &nWritten);            // copy pk_yours
        Z2BYTES(pk_mine, CTX + maclen + pLen, &nWritten);      // copy pk_mine
    }
    memcpy(CTX+maclen+2*pLen,&indexBE,sizeof(indexBE)); // copy index to CTX
    unsigned char K[maclen]; // key buffer
    memset(K,0,maclen); // make sure k is all zeros
    // compute the first key chunk
    HMAC(EVP_sha512(), PRK, maclen, CTX, ctxlen, K, 0); // k = HMAC(PRK, CTX)
    // now copy the first key chunk to the key buffer
    size_t copylen = buflen < maclen ? buflen : maclen; // length to copy
    memcpy(keybuf, K, copylen); // copy key chunk to key buffer
    // now we need to generate the rest of the key chunks
    size_t bytesLeft = buflen - copylen;
    while (bytesLeft){
        index++;
        indexBE = htobe64(index); // convert index to big endian
        memcpy(CTX+maclen+2*pLen,&indexBE,sizeof(indexBE)); // copy index to CTX
        memcpy(CTX, K, maclen); // copy previous key chunk to CTX
        // compute the next key chunk
        HMAC(EVP_sha512(), PRK, maclen, CTX, ctxlen, K, 0); // k = HMAC(PRK, CTX)
        // now copy the key chunk to the key buffer
        copylen = bytesLeft < maclen ? bytesLeft : maclen; // length to copy
        keybuf += copylen; // move to next key chunk in key buffer
        memcpy(keybuf, K, copylen); // copy key chunk to key buffer
        bytesLeft -= copylen; // decrease bytes left
    }
    // erasae sensitive data
    memset(SK, 0, pLen); // erase SK
    memset(PRK, 0, maclen); // erase PRK
    memset(K, 0, maclen); // erase K
    memset(CTX, 0, ctxlen); // erase CTX

    return 0;


}