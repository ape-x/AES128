//
//  CSHA512.h
//  AES
//
//  Created by Mihnea Stefan on 15.11.2020.
//

#ifndef CSHA512_h
#define CSHA512_h

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

extern unsigned long int H[];
void hashcomputation(char *input);
void cleanMessageDigest(void);

#endif /* CSHA512_h */
