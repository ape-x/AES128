//
//  AES128.c
//  AES
//
//  Created by Mihnea Stefan on 14.11.2020.
//

#include "AES128.h"

#define BLOCK_SIZE 16 // 128 bit blocks
#define KEY_SIZE 16 // 128 bit-long key

uint8_t expandedKey[10][KEY_SIZE];

uint8_t rcon[10][4] =
{
    0x01,    0,    0,    0,
    0x02,    0,    0,    0,
    0x04,    0,    0,    0,
    0x08,    0,    0,    0,
    0x10,    0,    0,    0,
    0x20,    0,    0,    0,
    0x40,    0,    0,    0,
    0x80,    0,    0,    0,
    0x1b,    0,    0,    0,
    0x36,    0,    0,    0
};

inline static void subBytes(uint8_t* state){
    for(int i=0;i<4;i++){
        state[i*4] = sBox[state[i*4]];
        state[i*4+1] = sBox[state[i*4+1]];
        state[i*4+2] = sBox[state[i*4+2]];
        state[i*4+3] = sBox[state[i*4+3]];
    }
}

inline static void invSubBytes(uint8_t* state){
    for(int i=0;i<4;i++){
        state[i*4] = inv_sBox[state[i*4]];
        state[i*4+1] = inv_sBox[state[i*4+1]];
        state[i*4+2] = inv_sBox[state[i*4+2]];
        state[i*4+3] = inv_sBox[state[i*4+3]];
    }
}


inline static void shiftRows(uint8_t* state){ // Looks like crap but it's faster than a crab
    uint8_t swap;
    swap = state[4];
    state[4] = state[5];
    state[5] = state[6];
    state[6] = state[7];
    state[7] = swap;
    swap = state[15];
    state[15] = state[14];
    state[14] = state[13];
    state[13] = state[12];
    state[12] = swap;
    (void)(state[8]^=state[10]), (void)(state[10]^=state[8]), state[8]^=state[10];
    (void)(state[9]^=state[11]), (void)(state[11]^=state[9]), state[9]^=state[11];
}


inline static void invShiftRows(uint8_t* state){
    uint8_t swap;
    swap = state[7];
    state[7] = state[6];
    state[6] = state[5];
    state[5] = state[4];
    state[4] = swap;
    swap = state[12];
    state[12] = state[13];
    state[13] = state[14];
    state[14] = state[15];
    state[15] = swap;
    (void)(state[8]^=state[10]), (void)(state[10]^=state[8]), state[8]^=state[10];
    (void)(state[9]^=state[11]), (void)(state[11]^=state[9]), state[9]^=state[11];
}

inline static void mixColumns(uint8_t* state){
    uint8_t s[4];
    for(int i=0;i<4;i++){
       s[0] = (mul2[state[i]] ^ mul3[state[i+4]] ^ state[i+8] ^ state[i+12]);
       s[1] = (state[i] ^ mul2[state[i+4]] ^ mul3[state[i+8]] ^ state[i+12]);
       s[2] = (state[i] ^ state[i+4] ^ mul2[state[i+8]] ^ mul3[state[i+12]]);
       s[3] = (mul3[state[i]] ^ state[i+4] ^ state[i+8] ^ mul2[state[i+12]]);
        state[i] = s[0];
        state[i+4] = s[1];
        state[i+8] = s[2];
        state[i+12] = s[3];
    }
}

inline static void invMixColumns(uint8_t* state){
    uint8_t s[4];
    for(int i=0;i<4;i++){
    s[0] = mul_14[state[i]] ^ mul_11[state[i+4]] ^ mul_13[state[i+8]] ^ mul_9[state[i+12]];
    s[1] = mul_9[state[i]] ^ mul_14[state[i+4]] ^ mul_11[state[i+8]] ^ mul_13[state[i+12]];
    s[2] = mul_13[state[i]] ^ mul_9[state[i+4]] ^ mul_14[state[i+8]] ^ mul_11[state[i+12]];
    s[3] = mul_11[state[i]] ^ mul_13[state[i+4]] ^ mul_9[state[i+8]] ^ mul_14[state[i+12]];
        state[i] = s[0];
        state[i+4] = s[1];
        state[i+8] = s[2];
        state[i+12] = s[3];
    }
}

 inline static void addRoundKey(uint8_t* state, uint8_t* roundKey){
    for(int i=0;i<4;i++){
        state[i*4]^=roundKey[i*4];
        state[i*4+1]^=roundKey[i*4+1];
        state[i*4+2]^=roundKey[i*4+2];
        state[i*4+3]^=roundKey[i*4+3];
    }
}

void keySchedule(uint8_t* key, int round){
    uint8_t first = key[3];
    uint8_t arr[4] = {key[3], key[7], key[11], key[15]};
    for(int i=0;i<3;i++){
        arr[i] = sBox[arr[i+1]];
    }
    arr[3] = sBox[first];
    for(int i=0;i<4;i++){
        key[i*4] = key[i*4] ^ arr[i] ^ rcon[round][i];
    }
    for(int i=1;i<4;i++){
        key[i] = key[i] ^ key[i-1];
        key[i+4] = key[i+4] ^ key[i+3];
        key[i+8] = key[i+8] ^ key[i+7];
        key[i+12] = key[i+12] ^ key[i+11];
    }
 }

void keyExpansion(uint8_t* key){
    uint8_t k[KEY_SIZE];
    for(int i=0;i<16;i++){
        k[i] = key[i];
    }
    for(int i=0;i<10;i++){
    keySchedule(k, i);
        for(int j=0;j<16;j++){
            expandedKey[i][j] = k[j];
        }
    }
}

void encryptBlock(uint8_t* state, uint8_t* encryption_key){
    addRoundKey(state, encryption_key);
    for(int i=0;i<9;i++){
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, &expandedKey[i]);
     }
     subBytes(state);
     shiftRows(state);
    addRoundKey(state, expandedKey[9]);
}

void decryptBlock(uint8_t *state, uint8_t* encryption_key){
    addRoundKey(state, &expandedKey[9]);
    for(int i = 8;i>=0;i--){
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, &expandedKey[i]);
        invMixColumns(state);
    }
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, encryption_key);
}
