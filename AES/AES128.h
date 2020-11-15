//
//  AES128.h
//  AES
//
//  Created by Mihnea Stefan on 14.11.2020.
//

#ifndef AES128_h
#define AES128_h

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mount.h>
#include "LookUpTables.h"

#define BLOCK_SIZE 16 // 128 bit blocks
#define KEY_SIZE 16 // 128 bit-long key

extern uint8_t expandedKey[10][KEY_SIZE];
extern uint8_t rcon[10][4];

void subBytes(uint8_t* state);
void invSubBytes(uint8_t* state);
void shiftRows(uint8_t* state);
void invShiftRows(uint8_t* state);
void mixColumns(uint8_t* state);
void invMixColumns(uint8_t* state);
void addRoundKey(uint8_t* state, uint8_t* roundKey);
void keySchedule(uint8_t* key, int round);
void keyExpansion(uint8_t* key);
void encryptBlock(uint8_t* state, uint8_t* encryption_key);
void decryptBlock(uint8_t *state, uint8_t* encryption_key);


#endif /* AES128_h */
