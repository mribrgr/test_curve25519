//
//  main.c
//  tester
//
//  Created by mribrgr on 03.03.19.
//  Copyright © 2019 mribrgr. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
// #include <stdint.h>

#include "curve25519/curve25519-donna.h"

#define KEY_LENGTH 32

/**
 Prints an uint8_t stream in hex.
 @param stream uint8_t stream
 @param len length of stream
 */
void print_hex_bytes(uint8_t *stream, int len)
{
    int i;
    for (i=0; i<len; i++) {
        printf("%02x", stream[i]);
    }
    printf("\n");
    
    return;
}

/**
 Generates random data with <func> and writes them to <secret> with the lenght len
 @param secret secret key where to write the random datas to
 @param len length of the key (currently only optimized for 32 Bytes)
 @param func function pointer which generates random datas
 */
void generate_rand_secret_32(uint8_t *secret, int len, void (*func)(void*,size_t))
{
    func(secret, len);
    
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    
    return;
}

int main(void)
{
    static const uint8_t basepoint[KEY_LENGTH] = {9};
    
    // generate my public & secret key
    static uint8_t mysecret[KEY_LENGTH], mypublic[KEY_LENGTH];
    generate_rand_secret_32(mysecret, KEY_LENGTH, arc4random_buf);
    curve25519_donna(mypublic, mysecret, basepoint);

    // generate their public & secret key (should be on another computer)
    static uint8_t theirsecret[KEY_LENGTH], theirpublic[KEY_LENGTH]; // in this example just random data
    generate_rand_secret_32(theirsecret, KEY_LENGTH, arc4random_buf);
    curve25519_donna(theirpublic, theirsecret, basepoint);
    
    // generate the shared keys
    uint8_t my_shared_key[KEY_LENGTH], their_shared_key[KEY_LENGTH];
    curve25519_donna(my_shared_key, mysecret, theirpublic);
    curve25519_donna(their_shared_key, theirsecret, mypublic);
    
    printf("mysecret:         "); print_hex_bytes(mysecret,         KEY_LENGTH);
    printf("mypublic:         "); print_hex_bytes(mypublic,         KEY_LENGTH);
    printf("theirsecret:      "); print_hex_bytes(theirsecret,      KEY_LENGTH);
    printf("theirpublic:      "); print_hex_bytes(theirpublic,      KEY_LENGTH);
    printf("my_shared_key:    "); print_hex_bytes(my_shared_key,    KEY_LENGTH);
    printf("their_shared_key: "); print_hex_bytes(their_shared_key, KEY_LENGTH);
    
    return 0;
}
