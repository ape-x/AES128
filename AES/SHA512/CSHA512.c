//
//  CHSA512.c
//  AES
//
//  Created by Mihnea Stefan on 15.11.2020.
//

#include "CSHA512.h"

unsigned long int K[] = { 0x428a2f98d728ae22 ,0x7137449123ef65cd ,0xb5c0fbcfec4d3b2f  ,0xe9b5dba58189dbbc  ,0x3956c25bf348b538  ,0x59f111f1b605d019  ,0x923f82a4af194f9b  ,0xab1c5ed5da6d8118  ,0xd807aa98a3030242  ,0x12835b0145706fbe  ,0x243185be4ee4b28c  ,0x550c7dc3d5ffb4e2
    ,0x72be5d74f27b896f  ,0x80deb1fe3b1696b1  ,0x9bdc06a725c71235  ,0xc19bf174cf692694  ,0xe49b69c19ef14ad2  ,0xefbe4786384f25e3  ,0x0fc19dc68b8cd5b5  ,0x240ca1cc77ac9c65  ,0x2de92c6f592b0275  ,0x4a7484aa6ea6e483  ,0x5cb0a9dcbd41fbd4  ,0x76f988da831153b5  ,0x983e5152ee66dfab  ,0xa831c66d2db43210  ,0xb00327c898fb213f  ,0xbf597fc7beef0ee4  ,0xc6e00bf33da88fc2  ,0xd5a79147930aa725  ,0x06ca6351e003826f  ,0x142929670a0e6e70  ,0x27b70a8546d22ffc  ,0x2e1b21385c26c926  ,0x4d2c6dfc5ac42aed  ,0x53380d139d95b3df  ,0x650a73548baf63de  ,0x766a0abb3c77b2a8  ,0x81c2c92e47edaee6  ,0x92722c851482353b  ,0xa2bfe8a14cf10364  ,0xa81a664bbc423001  ,0xc24b8b70d0f89791  ,0xc76c51a30654be30  ,0xd192e819d6ef5218  ,0xd69906245565a910  ,0xf40e35855771202a  ,0x106aa07032bbd1b8 ,0x19a4c116b8d2d0c8  ,0x1e376c085141ab53  ,0x2748774cdf8eeb99  ,0x34b0bcb5e19b48a8  ,0x391c0cb3c5c95a63  ,0x4ed8aa4ae3418acb  ,0x5b9cca4f7763e373  ,0x682e6ff3d6b2b8a3  ,0x748f82ee5defb2fc  ,0x78a5636f43172f60  ,0x84c87814a1f0ab72  ,0x8cc702081a6439ec  ,0x90befffa23631e28  ,0xa4506cebde82bde9 ,0xbef9a3f7b2c67915  ,0xc67178f2e372532b  ,0xca273eceea26619c  ,0xd186b8c721c0c207  ,0xeada7dd6cde0eb1e  ,0xf57d4f7fee6ed178  ,0x06f067aa72176fba  ,0x0a637dc5a2c898a6  ,0x113f9804bef90dae  ,0x1b710b35131c471b  ,0x28db77f523047d84 ,0x32caab7b40c72493  ,0x3c9ebe0a15c9bebc  ,0x431d67c49c100d4c  ,0x4cc5d4becb3e42b6  ,0x597f299cfc657e2a  ,0x5fcb6fab3ad6faec  ,0x6c44198c4a475817};

unsigned long int H[] = {0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179};

inline static unsigned long  int rotr(unsigned long  int number, int times){
    return (number>>times|number<<(64-times));
}
inline static unsigned long  int lowerSigma0(unsigned  long int number){
    return rotr(number,1)^rotr(number,8)^(number>>7);
}
inline static unsigned long  int lowerSigma1(unsigned  long int number){
    return rotr(number,19)^rotr(number,61)^(number>>6);
}
inline static unsigned long int  Sigma0(unsigned  long int number){
    return rotr(number,28)^rotr(number,34)^rotr(number,39);
}
inline static unsigned long  int Sigma1(unsigned  long int number){
    return rotr(number,14)^rotr(number,18)^rotr(number,41);
}
inline static unsigned long int Ch(unsigned long int x, unsigned long int y, unsigned long int z){
    return ((x&y)^(~x&z));
}
inline static unsigned long int Maj(unsigned long int x, unsigned long int y, unsigned long int z){
    return  ((x&y)^(x&z)^(y&z));
}

void cleanMessageDigest(){
    H[0]=0x6a09e667f3bcc908;
    H[1]=0xbb67ae8584caa73b;
    H[2]=0x3c6ef372fe94f82b;
    H[3]=0xa54ff53a5f1d36f1;
    H[4]=0x510e527fade682d1;
    H[5]=0x9b05688c2b3e6c1f;
    H[6]=0x1f83d9abfb41bd6b;
    H[7]=0x5be0cd19137e2179;
}

void hashcomputation(char* input){
    unsigned int* binary;
    int length = (int)strlen(input);
    unsigned long int W[80];
    int k = 0;
    
    k = 112-(((length)%128)+1); // hash preprocessing
    if(k<0){
        k=k*(-1);
        k=128-k;
    }
    
    binary=(unsigned int*)calloc(length+k+1+16, sizeof(int)); // [message in ascii]+[1 bit]+[k 0 padding] + [message length in bits - big endian last 128 bits]
    
    for(int i=0;i<strlen(input);i++){
        binary[i] = input[i];
        }
    
    if(length*8<256){
        
        binary[length+k+16] = length*8;
        binary[strlen(input)] = 128;
        
    }else{//Length overflows in 8 bit unsigned int
        int counter = (int)strlen(input)+16+k;
        int buffer = (length*8)/256;
        binary[counter] = (length*8)%256;
        while(1){
            counter-=1;
            binary[counter] = buffer%256;
            buffer = buffer/256;
            if(buffer<256){
                if(counter==strlen(input)+k){
                    binary[counter] = buffer+128;
                    break;
                }else{
                    binary[strlen(input)] = 128;
                    counter--;
                    binary[counter] = buffer;
                    break;
                }
            }
        }
    }

    for(int chunk = 0;chunk<(strlen(input)+1+16+k)/128;chunk++){//CHUNK ITERATION
           
    int j = 0+(chunk*128);

    for(int i=0;i<16;i++){
        W[i] = (unsigned long)binary[j+0]<<56|(unsigned long)binary[j+1]<<48;
        W[i]+= (unsigned long)binary[j+2]<<40|(unsigned long)binary[j+3]<<32;
        W[i]+= binary[j+4]<<24|binary[j+5]<<16;
        W[i]+= binary[j+6]<<8|binary[j+7]<<0;
        if(W[i]<0){
            W[i] = (unsigned long)((W[i]+1)*(-1)+1);
        }
        j+=8;
    }
    for(int t = 16;t<80;t++){
        W[t] = lowerSigma1(W[t-2])+W[t-7]+lowerSigma0(W[t-15])+W[t-16];
    }
    
    unsigned long int a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    
    for(int t = 0;t<80;t++){
        unsigned long int T1 = h+Sigma1(e)+Ch(e, f, g)+K[t]+W[t];
        unsigned long int T2 = Sigma0(a)+Maj(a,b,c);
        h=g;
        g=f;
        f=e;
        e = d + T1;
        d=c;
        c=b;
        b=a;
        a=T1 +T2;
    }
    
    H[0]+=a;
    H[1]+=b;
    H[2]+=c;
    H[3]+=d;
    H[4]+=e;
    H[5]+=f;
    H[6]+=g;
    H[7]+=h;
    }
    free(binary);
}
