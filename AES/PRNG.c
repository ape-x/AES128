//
//  PRNG.c
//  AES
//
//  Created by Mihnea Stefan on 16.11.2020.
//

#include "PRNG.h"
#define MTP 32 // Maximum Tap Positions

typedef struct {
    uint8_t positions[MTP];
    uint8_t numberOfPositions;
} pvector;


inline static bool FBT(unsigned long int number, int position){ // find bit value
    return (number & (1 << (position-1)))>>(position-1);
}

inline static uint8_t logicalFunction(uint8_t *array){
    uint8_t number = array[0];
    for(int i=1;i<4;i++)
        number^=array[i];
    return number;
}

inline static uint32_t combineTo32(uint8_t* seed){
    return ((uint32_t)seed[3]<<24) | ((uint32_t)seed[2]<<16) | ((uint32_t)seed[1]<<8) | ((uint32_t)seed[0]<<0);
}

inline static void distributeTo8(uint64_t number, uint8_t* array){
    for(int i=0;i<8;i++)
        array[i] = (uint8_t)(number>>i*8);
}

inline static void push_back(pvector* vec, uint8_t number){
    vec->positions[vec->numberOfPositions] = number;
    vec->numberOfPositions+=1;
}

inline static void populatePolynomial(pvector *vec, uint64_t number){
    vec->numberOfPositions = 0;
    for(int i=0;i<64;i++)
        if(FBT(number, i))
            push_back(vec, i);
}


void LFSR(uint8_t* seed){
    
    bool gateBit[4], outputBit[4];
    uint8_t containerSize = 0;
    uint32_t _seed[4] = {combineTo32(seed), combineTo32(&seed[4]), combineTo32(&seed[8]), combineTo32(&seed[12])};
    pvector polynomials[4]; // Vectors containing the tap positions of the LFSR
    uint64_t container = 0;
    
    for(int i=0;i<4;i++)
        populatePolynomial(&polynomials[i], _seed[i]); // Creating the polynomial of the integer
    
    for(int i=0;i<2;i++){
        while(containerSize<64){
            for(int j=0;j<4;j++){
                gateBit[j] = FBT(_seed[j], polynomials[j].positions[0]);
                
                outputBit[j] = (_seed[j]%2==0) ? 0 : 1;
                
                for(int k=1;k<polynomials[j].numberOfPositions;k++)
                    gateBit[j]^=FBT(_seed[j], polynomials[j].positions[k]);
                
                _seed[j]>>=1;
                if(gateBit[j])
                    _seed[j]|=UINT32_MAX/2+1;
            }
            
            container>>=1;
            containerSize++;
            if(outputBit[0]^outputBit[1]^outputBit[2]^outputBit[3])
                    container|=UINT64_MAX/2+1;
            
        }
        containerSize = 0;
        distributeTo8(container, &seed[i*8]);
    }
    
}

uint8_t* PRNG(char* seed){
    uint8_t counter = 0;
    uint8_t* generatedArray = (uint8_t*)malloc(16*sizeof(uint8_t));
    uint8_t distributedInt[8][8];
    uint64_t _H[8];
    
    hashcomputation(seed);
    memcpy(_H, H, 8*sizeof(uint64_t));
    cleanMessageDigest();

    for(int i=0;i<8;i++){
        distributeTo8(_H[i], distributedInt[i]);
        LFSR(distributedInt[i]);
    }
    
    for(int i=0;i<8;i++){
        generatedArray[i] = logicalFunction(&distributedInt[counter][0]);
        generatedArray[i+8] = logicalFunction(&distributedInt[counter][4]);
        counter++;
    }
    
    return generatedArray;
}
