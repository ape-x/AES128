//
//  main.cpp
//  AES128
//
//  Created by Mihnea Stefan on 19/09/2020.
//  Copyright © 2020 Mihnea Stefan. All rights reserved.
//


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

uint8_t expandedKey[10][KEY_SIZE];

uint8_t rcon[10][4] =
{
    0x01,	0,	0,	0,
    0x02,	0,	0,	0,
    0x04,	0,	0,	0,
    0x08,	0,	0,	0,
    0x10,	0,	0,	0,
    0x20,	0,	0,	0,
    0x40,	0,	0,	0,
    0x80,	0,	0,	0,
    0x1b,	0,	0,	0,
    0x36,	0,	0,	0
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

 static void keySchedule(uint8_t* key, int round){
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

void encryption(uint8_t *text, uint8_t* encryption_key, long bytes){
		uint8_t* blockCounter;
		long blocks = bytes/BLOCK_SIZE;
    keyExpansion(encryption_key);
    for(int i=0;i<blocks;i++){
        blockCounter=&text[i*BLOCK_SIZE];
        encryptBlock(blockCounter, encryption_key);
    }
}

void decryption(uint8_t *text, uint8_t* encryption_key, long bytes){
		uint8_t* blockCounter;
		long blocks = bytes/BLOCK_SIZE;
    keyExpansion(encryption_key);
		for(int i=0;i<blocks;i++){
        blockCounter=&text[i*BLOCK_SIZE];
        decryptBlock(blockCounter, encryption_key);
    }
}

bool searchForFile(char* path, char* searchedItem){
		FILE* checkFile;
		printf("\nEnter path to %s", searchedItem);
		scanf("%s", path);
		if((checkFile = fopen(path, "r"))== NULL){
				fclose(checkFile);
				return false;
		}
		fclose(checkFile);
		return true;
}

long getFileSize(char* fileName){
		struct stat fSize;
		stat(fileName, &fSize);
		return fSize.st_size;
}

void cryptographicMotor(){

		uint8_t padding = 0;
		uint8_t *buffer;
		uint8_t functionality;
		FILE* fileReader;
		char key[BLOCK_SIZE];
		char outputName[20];
		char filePath[PATH_MAX];
		char keyPath[PATH_MAX];
		long fileSize;
		void (*controller[])(uint8_t*, uint8_t*, int) = {encryption, decryption};
				
		printf("\nSelect functionality\n1 - Encryption\n2 - Decryption\n");
		scanf("%d", &functionality);

		if(functionality != 1 && functionality != 2)
				return;
		
		if(searchForFile(filePath, "file ") == false || // check if files exist
			 searchForFile(keyPath, "key ") == false){
				printf("\nFile does not exist or could not be opened");
				return;
		}
		
		fileReader = fopen(keyPath, "r");
		fgets(key, KEY_SIZE, fileReader);
		fclose(fileReader);
		fileSize = getFileSize(filePath);
		
		if(fileSize % 16 != 0)
				padding = (fileSize/BLOCK_SIZE+1)*16 - fileSize;
		
		buffer = (uint8_t*)malloc((fileSize+padding)*sizeof(uint8_t));
		
		if(buffer == NULL){
				printf("Insufficient memory");
				return;
		}

		for(long i = fileSize;i<fileSize+padding;i++)	// padding last block with white spaces
				buffer[i] = 32;
		
		fileReader = fopen(filePath, "r");
		fread(buffer, 1, fileSize, fileReader);
		fclose(fileReader);

		controller[functionality-1](buffer, key, fileSize+padding);
		
		printf("\nEnter name of output file ");
		scanf("%s", &outputName);
		
		fileReader = fopen(outputName, "w");
		fwrite(buffer, 1, fileSize+padding, fileReader);
		fclose(fileReader);
}
