//
//  CBC.c
//  AES
//
//  Created by Mihnea Stefan on 14.11.2020.
//

#include "ModesOfOperation.h"


void generateInitializationVector(){
    
}

void encryptionCBC(uint8_t* text, uint8_t* encryption_key, long bytes){
    uint8_t* blockCounter;
    long blocks = bytes/BLOCK_SIZE;
    keyExpansion(encryption_key);
    
    for(int i=0;i<blocks;i++)
        encryptBlock(&text[i*BLOCK_SIZE], encryption_key);
    
}


void encryptionECB(uint8_t *text, uint8_t* encryption_key, long bytes){
        uint8_t* blockCounter;
        long blocks = bytes/BLOCK_SIZE;
    keyExpansion(encryption_key);
    for(int i=0;i<blocks;i++){
        blockCounter=&text[i*BLOCK_SIZE];
        encryptBlock(blockCounter, encryption_key);
    }
}

void decryptionECB(uint8_t *text, uint8_t* encryption_key, long bytes){
        uint8_t* blockCounter;
        long blocks = bytes/BLOCK_SIZE;
    keyExpansion(encryption_key);
        for(int i=0;i<blocks;i++){
        blockCounter=&text[i*BLOCK_SIZE];
        decryptBlock(blockCounter, encryption_key);
    }
}
