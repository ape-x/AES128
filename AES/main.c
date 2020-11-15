//
//  main.cpp
//  AES128
//
//  Created by Mihnea Stefan on 19/09/2020.
//  Copyright © 2020 Mihnea Stefan. All rights reserved.
//


#include "LookUpTables.h"
#include "AES128.h"
#include "CSHA512.h"

enum ModesOfOperation {
    ECB = 1,
    CBC = 2,
};

uint8_t* derivationProcess(uint8_t* array){
    uint8_t *derivedArray = (uint8_t*)malloc(KEY_SIZE*sizeof(uint8_t));
    
    memcpy(derivedArray, array, KEY_SIZE);
    
    shiftRows(derivedArray);
    mixColumns(derivedArray);
    subBytes(derivedArray);
    
    for(int i=0;i<KEY_SIZE;i++)
        derivedArray[i]^=array[i];
    
    encryptBlock(derivedArray, array);
   
    return derivedArray;
}
 
 uint8_t* generateInitializationVector(uint8_t* key, uint8_t* state, uint8_t* salt){ // We take advantage of the substitution-permutation network used in AES to perform an IV generation using its avalanche-effect
     uint8_t *derivedKey = derivationProcess(key);
     uint8_t *derivedState = derivationProcess(state);
     uint8_t *IV = (uint8_t*)malloc(KEY_SIZE*sizeof(uint8_t));
     
     encryptBlock(derivedState, derivedKey);
     encryptBlock(derivedKey, salt);
     
     for(int i=0;i<KEY_SIZE;i++)
        IV[i] = derivedKey[i] ^ derivedState[i] ^ salt[i];
    
     free(derivedKey);
     free(derivedState);
     
     return IV;
 }

 void encryptionCBC(uint8_t* text, uint8_t* encryption_key, long bytes){
     long blocks = bytes/BLOCK_SIZE;
     uint8_t counter = 0;
     uint8_t salt[BLOCK_SIZE];
     uint8_t *IV;

     memcpy(salt, encryption_key, 16);
     hashcomputation((char*)salt);
     
     for(int i=0;i<8;i++){
        salt[i] = (uint8_t)H[i];
        salt[i+8] = (uint8_t)H[i]^encryption_key[i];
     }

     cleanMessageDigest();
     
     IV = generateInitializationVector(encryption_key, text, salt);
     
     keyExpansion(encryption_key);
     addRoundKey(text, IV);
     encryptBlock(text, encryption_key);
     
     for(int i=1;i<blocks;i++){
         addRoundKey(&text[i*BLOCK_SIZE], &text[(i-1)*BLOCK_SIZE]);
         encryptBlock(&text[i*BLOCK_SIZE], encryption_key);
     }
     
     for(long c = bytes-16;c<bytes;c++,counter++)
        text[c] = IV[counter];
     
     free(IV);
 }

void decryptionCBC(uint8_t* text, uint8_t* encryption_key, long bytes){
    uint8_t counter = 0;
    long blocks = bytes/BLOCK_SIZE;
    uint8_t IV[KEY_SIZE];
    keyExpansion(encryption_key);
    
    for(long i = bytes-2*BLOCK_SIZE;i<bytes-BLOCK_SIZE;i++,counter++)
        IV[counter] = text[i];

    for(long i=blocks-2;i>0;i--){
        decryptBlock(&text[i*BLOCK_SIZE], encryption_key);
        addRoundKey(&text[i*BLOCK_SIZE], &text[(i-1)*BLOCK_SIZE]);
    }
    
    decryptBlock(text, encryption_key);
    addRoundKey(text, IV);
    addRoundKey(&text[bytes-2*BLOCK_SIZE], &text[bytes-2*BLOCK_SIZE]); // XOR IV with itself to set its content to 0
}


 void encryptionECB(uint8_t *text, uint8_t* encryption_key, long bytes){
         long blocks = bytes/BLOCK_SIZE;
        keyExpansion(encryption_key);
     
     for(int i=0;i<blocks;i++)
         encryptBlock(&text[i*BLOCK_SIZE], encryption_key);
     
 }

 void decryptionECB(uint8_t *text, uint8_t* encryption_key, long bytes){
         long blocks = bytes/BLOCK_SIZE;
         keyExpansion(encryption_key);
        
    for(int i=0;i<blocks;i++)
         decryptBlock(&text[i*BLOCK_SIZE], encryption_key);
 }


FILE* searchForFilePlus(char* path, char* searchedItem){
		printf("\nEnter path to %s\t", searchedItem);
		scanf("%s", path);
		return fopen(path, "r");
}

long getFileSize(char* fileName){
		struct stat fSize;
		stat(fileName, &fSize);
		return fSize.st_size;
}

/*
 The Cryptographic Coat manages everything outside the encryption process, such as file handling, providing an interface to the
 available modes of operation.
 The task of any encryption* decryption* function is to perform cryptographic operations on its parameters, anything else is taken care of by the motor.
 */

void cryptographicCoat(){

		uint8_t padding = 0;
		uint8_t functionality;
        uint8_t modeOfOperation;
        uint8_t *buffer;
		FILE* fileReader;
		FILE* keyReader;
		uint8_t key[BLOCK_SIZE];
		char outputName[20];
		char filePath[PATH_MAX];
		char keyPath[PATH_MAX];
		long fileSize;
        void (*controller[2][2])(uint8_t*, uint8_t*, long) = { {encryptionECB, encryptionCBC }, { decryptionECB, decryptionCBC }  };
        
    
		printf("\nSelect functionality\n1 - Encryption\n2 - Decryption\n");
		scanf("%d", &functionality);
    
        if(functionality != 1 && functionality != 2)
                return;
    
        printf("\nSelect mode of operation\n1 - ECB\n2 - CBC\n");
        scanf("%d", &modeOfOperation);
    
        if(modeOfOperation != 1 && modeOfOperation != 2)
            return;
    		
		if(!(fileReader = searchForFilePlus(filePath, "file ")) || // check if files exist
			 !(keyReader = searchForFilePlus(keyPath, "key "))){
				printf("\nFile does not exist or could not be opened");
				return;
		}
		
        fread(key, 1, KEY_SIZE, keyReader);
		fclose(keyReader);
		fileSize = getFileSize(filePath);
    
    if(modeOfOperation == CBC)  //Checks the mode of operation in order to determine whether or not to insert the IV in the file
            fileSize+=BLOCK_SIZE;
    
		
		buffer = (uint8_t*)malloc((fileSize+padding)*sizeof(uint8_t));
		
		if(buffer == NULL){
				printf("Insufficient memory");
				return;
		}
		
		if(fileSize % BLOCK_SIZE != 0){
				padding = (fileSize/BLOCK_SIZE+1)*BLOCK_SIZE - fileSize;
				for(long i = fileSize;i<fileSize+padding;i++)	// padding last block with white spaces
						buffer[i] = 32;
		}
		
		fread(buffer, 1, fileSize, fileReader);
		fclose(fileReader);

        clock_t t;
        t = clock();
        controller[functionality-1][modeOfOperation-1](buffer, key, fileSize+padding);
        t = clock() - t;
        double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds
        printf("\nTime %f\nSize %ld", time_taken, ((fileSize+padding)/1024)/1024);
    
		printf("\nEnter name of output file ");
		scanf("%s", &outputName);
		
		fileReader = fopen(outputName, "w");
    
        fwrite(buffer, 1, fileSize+padding, fileReader);
		fclose(fileReader);
		free(buffer);
}

int main(){
    
    chdir("/Users/apex/Documents/AES128-ECB");
    cryptographicCoat();
   
}
/*
 
 57 35 8e ca 24 78 27 ae 36 57 ed ae 41 1e 40 c6

 
 
 */
