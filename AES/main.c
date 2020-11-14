//
//  main.cpp
//  AES128
//
//  Created by Mihnea Stefan on 19/09/2020.
//  Copyright © 2020 Mihnea Stefan. All rights reserved.
//


#include "LookUpTables.h"
#include "AES128.h"
#include "ModesOfOperation.h"


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

void cryptographicMotor(){

		uint8_t padding = 0;
		uint8_t *buffer;
		uint8_t functionality;
		FILE* fileReader;
		FILE* keyReader;
		char key[BLOCK_SIZE];
		char outputName[20];
		char filePath[PATH_MAX];
		char keyPath[PATH_MAX];
		long fileSize;
		void (*controller[])(uint8_t*, uint8_t*, long) = {   encryptionECB, decryptionECB  };
				
		printf("\nSelect functionality\n1 - Encryption\n2 - Decryption\n");
		scanf("%d", &functionality);

		if(functionality != 1 && functionality != 2)
				return;
		
		if(!(fileReader = searchForFilePlus(filePath, "file ")) || // check if files exist
			 !(keyReader = searchForFilePlus(keyPath, "key "))){
				printf("\nFile does not exist or could not be opened");
				return;
		}
		
		fgets(key, KEY_SIZE, keyReader);
		fclose(keyReader);
		fileSize = getFileSize(filePath);
		
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

		controller[functionality-1](buffer, key, fileSize+padding);
		
		printf("\nEnter name of output file ");
		scanf("%s", &outputName);
		
		fileReader = fopen(outputName, "w");
		fwrite(buffer, 1, fileSize+padding, fileReader);
		fclose(fileReader);
		free(buffer);
}

int main(){
    
}
