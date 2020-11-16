//
//  PRNG.c
//  AES
//
//  Created by Mihnea Stefan on 16.11.2020.
//

#include "PRNG.h"


inline static bool FBT(uint8_t number, uint8_t position){ // find bit value
    return (number & (1 << (position-1)))>>(position-1);
}

inline static bool produceBit(unsigned long int number, uint8_t* positions){
    return (FBT(number, positions[0])^FBT(number,positions[1]))^(FBT(number,positions[2])^FBT(number,positions[3]));
}


uint8_t* PRNG(char* seed){
    bool outputBit, gateBit;
    uint8_t* generatedArray = (uint8_t*)malloc(8*sizeof(uint8_t));
    uint8_t positions[] = { 7, 15, 31, 60};
    unsigned long int auxiliaryArray[8] = {0 , 0 , 0 , 0 , 0 , 0, 0 , 0};
    unsigned long int LFSR[8];
    
    hashcomputation(seed);
    
    for(int i=0;i<8;i++)
        LFSR[i] = H[i];
    
    cleanMessageDigest();
    
    for(int i=0;i<8;i++){
        for(int j=0;j<256;j++){
            
            gateBit = produceBit(LFSR[i] , positions);
            
            if(LFSR[i]%2==0) // If number is even, the LSB is 0, thus, the output will be 0
                outputBit = 0;
            else
                outputBit = 1;
            
            LFSR[i]>>=1;
            auxiliaryArray[i]>>=1;
            
            if(gateBit) // If the product of the gate is 1, we set the MSB to 1
                LFSR[i]|=UINT64_MAX/2+1;
            if(outputBit)
                auxiliaryArray[i]|=UINT64_MAX/2+1;
        }
        
        generatedArray[i] = (uint8_t)(auxiliaryArray[i]);
    }
    
    return generatedArray;
}
