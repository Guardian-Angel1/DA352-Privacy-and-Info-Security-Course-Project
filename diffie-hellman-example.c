#include <stdio.h>
#include<gmp.h>
#include<string.h>
#include<stdlib.h>
#include "diffie-hellman.h"


int main(){

    // if for some reason you wanted to make new DH parameters
    // you would call initFromScratch(...) here instead;

    if(init("dhparams.txt") == 0){
        gmp_printf("Successfully read DH params:\nq = %Zd\np = %Zd\ng = %Zd\n",q,p,g);   
    }

    // if(initFromScratch(256, 2048) == 0){
    //     gmp_printf("Successfully generated DH params:\nq = %Zd\np = %Zd\ng = %Zd\n", q, p, g);   
    // } else {
    //     fprintf(stderr, "Failed to generate DH parameters.\n");
    //     return 1;
    // }

    // ALICE
    NEWZ(a); // Alice's secret key (a random exponent)
    NEWZ(A); // Alice's public key (g^a mod p)
    dhGen(a,A); // generate Alice's keys
    // BOB
    NEWZ(b); // Bob's secret key (a random exponent)
    NEWZ(B); // Bob's public key (g^b mod p)
    dhGen(b,B); // generate Bob's keys
    // now Alice and Bob can compute the shared secret
    const size_t klen = 128; // length of key in bytes
    // Alice computes the shared secret
    unsigned char kA[klen]; // Alice's shared secret
    dhFinal(a,A,B,kA,klen); // compute shared secret
    // Bob computes the shared secret
    unsigned char kB[klen]; // Bob's shared secret
    dhFinal(b,B,A,kB,klen); // compute shared secret

    // make sure the keys are the same
    if(memcmp(kA,kB,klen) == 0){
        printf("Alice and Bob have the same key! \n");
    } else {
        printf("Shared secret keys do not match!\n");
    }
    printf("Alice's key: \n");
    for(size_t i = 0; i < klen; i++){
        printf("%02x ",kA[i]);
    }
    printf("\nBob's key: \n");
    for(size_t i = 0; i < klen; i++){
        printf("%02x ",kB[i]);
    }
    printf("\n");
    return 0;
}