//
//  CBC.h
//  AES
//
//  Created by Mihnea Stefan on 14.11.2020.
//

#ifndef CBC_h
#define CBC_h

#include "AES128.h"
#include <stdio.h>

void encryptionECB(uint8_t *text, uint8_t *encryption_key, long bytes);
void decryptionECB(uint8_t *text, uint8_t *encryption_key, long bytes);

void encryptionCBC(uint8_t *text, uint8_t *encryption_key, long bytes);
void decryptionCBC(uint8_t *text, uint8_t *encryption_key, long bytes);




#endif /* CBC_h */
