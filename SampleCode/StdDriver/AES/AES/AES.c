/******************************************************************************
 * @file     main.c
 * @brief
 *           Show how to implement software AES.
 * @note
 * Copyright (C) 2019 Nuvoton Technology Corp. All rights reserved.
 ******************************************************************************/
#include <stdio.h>
#include "NuMicro.h"
#include <string.h>




/*****************************************************************************/
/* Define                                                                    */
/*****************************************************************************/
/* The number of columns comprising a state in AES. This is a constant in AES. Value=4 */
#define NB 4
/* The number of 32 bit words in a key */
#define NK 4
/* Key length in bytes [128 bit] */
#define KEYLEN 16
/* The number of rounds in AES Cipher. */
#define NR 10

/* jcallan@github points out that declaring Multiply as a function
 reduces code size considerably with the Keil ARM compiler.
 See this link for more information: https://github.com/kokke/tiny-AES128-C/pull/3
*/
#ifndef MULTIPLY_AS_A_FUNCTION
#define MULTIPLY_AS_A_FUNCTION 0
#endif

/*****************************************************************************/
/* Global variables:                                                         */
/*****************************************************************************/
unsigned int g_i8T2, g_i8T1;

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
/* state - array holding the intermediate results during decryption. */
typedef uint8_t sState_t[4][4];
static sState_t* s_pu8State;

/* The array that stores the round keys. */
static uint8_t s_au8RoundKey[176];

/* The Key input to the AES Program */
static const uint8_t* s_pu8Key;

/* Initial Vector used only for CBC mode */
static uint8_t* s_pu8Iv;


/* The lookup-tables are marked const so they can be placed in read-only storage instead of RAM  */
/* The numbers below can be computed dynamically trading ROM for RAM -                           */
/* This can be useful in (embedded) bootloader applications, where ROM is often limited.         */
static const uint8_t s_au8Sbox[256] = {
    /* 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F */
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t s_au8Rsbox[256] =
{   0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};


/* The round constant word array, Rcon[i], contains the values given by                  */
/* x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)   */
/* Note that i starts at 1, not 0).                                                      */
static const uint8_t s_au8Rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
};




/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
static uint8_t GetSBoxValue(uint8_t num)
{
    return s_au8Sbox[num];
}

static uint8_t GetSBoxInvert(uint8_t num)
{
    return s_au8Rsbox[num];
}

/* This function produces NB(Nr+1) round keys. The round keys are used in each round to decrypt the states. */
static void KeyExpansion(void)
{
    uint32_t i, j, k;
    uint8_t au8Tempa[4]; /* Used for the column/row operations */

    /* The first round key is the key itself. */
    for (i = 0; i < NK; ++i)
    {
        s_au8RoundKey[(i * 4) + 0] = s_pu8Key[(i * 4) + 0];
        s_au8RoundKey[(i * 4) + 1] = s_pu8Key[(i * 4) + 1];
        s_au8RoundKey[(i * 4) + 2] = s_pu8Key[(i * 4) + 2];
        s_au8RoundKey[(i * 4) + 3] = s_pu8Key[(i * 4) + 3];
    }

    /* All other round keys are found from the previous round keys. */
    for (; (i < (NB * (NR + 1))); ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            au8Tempa[j] = s_au8RoundKey[(i - 1) * 4 + j];
        }
        if (i % NK == 0)
        {
            /* This function rotates the 4 bytes in a word to the left once. */
            /* [a0,a1,a2,a3] becomes [a1,a2,a3,a0]                           */

            /* Function RotWord() */
            {
                k = au8Tempa[0];
                au8Tempa[0] = au8Tempa[1];
                au8Tempa[1] = au8Tempa[2];
                au8Tempa[2] = au8Tempa[3];
                au8Tempa[3] = k;
            }

            /* SubWord() is a function that takes a four-byte input word and           */
            /* applies the S-box to each of the four bytes to produce an output word.  */

            /* Function Subword()                                                      */
            {
                au8Tempa[0] = GetSBoxValue(au8Tempa[0]);
                au8Tempa[1] = GetSBoxValue(au8Tempa[1]);
                au8Tempa[2] = GetSBoxValue(au8Tempa[2]);
                au8Tempa[3] = GetSBoxValue(au8Tempa[3]);
            }

            au8Tempa[0] = au8Tempa[0] ^ s_au8Rcon[i / NK];
        }
        else if (NK > 6 && i % NK == 4)
        {
            /* Function Subword() */
            {
                au8Tempa[0] = GetSBoxValue(au8Tempa[0]);
                au8Tempa[1] = GetSBoxValue(au8Tempa[1]);
                au8Tempa[2] = GetSBoxValue(au8Tempa[2]);
                au8Tempa[3] = GetSBoxValue(au8Tempa[3]);
            }
        }
        s_au8RoundKey[i * 4 + 0] = s_au8RoundKey[(i - NK) * 4 + 0] ^ au8Tempa[0];
        s_au8RoundKey[i * 4 + 1] = s_au8RoundKey[(i - NK) * 4 + 1] ^ au8Tempa[1];
        s_au8RoundKey[i * 4 + 2] = s_au8RoundKey[(i - NK) * 4 + 2] ^ au8Tempa[2];
        s_au8RoundKey[i * 4 + 3] = s_au8RoundKey[(i - NK) * 4 + 3] ^ au8Tempa[3];
    }
}

/* This function adds the round key to state.                 */
/* The round key is added to the state by an XOR function.    */
static void AddRoundKey(uint8_t round)
{
    uint8_t i, j;
    for (i = 0; i<4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*s_pu8State)[i][j] ^= s_au8RoundKey[round * NB * 4 + i * NB + j];
        }
    }
}

/* The SubBytes Function Substitutes the values in the */
/* state matrix with values in an S-box.               */
static void SubBytes(void)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*s_pu8State)[j][i] = GetSBoxValue((*s_pu8State)[j][i]);
        }
    }
}

/* The ShiftRows() function shifts the rows in the state to the left.   */
/* Each row is shifted with different offset.                           */
/* Offset = Row number. So the first row is not shifted.                */
static void ShiftRows(void)
{
    uint8_t u8Temp;

    /* Rotate first row 1 columns to left */
    u8Temp = (*s_pu8State)[0][1];
    (*s_pu8State)[0][1] = (*s_pu8State)[1][1];
    (*s_pu8State)[1][1] = (*s_pu8State)[2][1];
    (*s_pu8State)[2][1] = (*s_pu8State)[3][1];
    (*s_pu8State)[3][1] = u8Temp;

    /* Rotate second row 2 columns to left */
    u8Temp = (*s_pu8State)[0][2];
    (*s_pu8State)[0][2] = (*s_pu8State)[2][2];
    (*s_pu8State)[2][2] = u8Temp;

    u8Temp = (*s_pu8State)[1][2];
    (*s_pu8State)[1][2] = (*s_pu8State)[3][2];
    (*s_pu8State)[3][2] = u8Temp;

    /* Rotate third row 3 columns to left */
    u8Temp = (*s_pu8State)[0][3];
    (*s_pu8State)[0][3] = (*s_pu8State)[3][3];
    (*s_pu8State)[3][3] = (*s_pu8State)[2][3];
    (*s_pu8State)[2][3] = (*s_pu8State)[1][3];
    (*s_pu8State)[1][3] = u8Temp;
}

static uint8_t Xtime(uint8_t x)
{
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

/* MixColumns function mixes the columns of the state matrix */
static void MixColumns(void)
{
    uint8_t i;
    uint8_t u8Tmp, u8Tm, u8t;
    for (i = 0; i < 4; ++i)
    {
        u8t = (*s_pu8State)[i][0];
        u8Tmp = (*s_pu8State)[i][0] ^ (*s_pu8State)[i][1] ^ (*s_pu8State)[i][2] ^ (*s_pu8State)[i][3];
        u8Tm = (*s_pu8State)[i][0] ^ (*s_pu8State)[i][1];
        u8Tm = Xtime(u8Tm);
        (*s_pu8State)[i][0] ^= u8Tm ^ u8Tmp;
        u8Tm = (*s_pu8State)[i][1] ^ (*s_pu8State)[i][2];
        u8Tm = Xtime(u8Tm);
        (*s_pu8State)[i][1] ^= u8Tm ^ u8Tmp;
        u8Tm = (*s_pu8State)[i][2] ^ (*s_pu8State)[i][3];
        u8Tm = Xtime(u8Tm);
        (*s_pu8State)[i][2] ^= u8Tm ^ u8Tmp;
        u8Tm = (*s_pu8State)[i][3] ^ u8t;
        u8Tm = Xtime(u8Tm);
        (*s_pu8State)[i][3] ^= u8Tm ^ u8Tmp;
    }
}

/* Multiply is used to multiply numbers in the field GF(2^8) */
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
    return (((y & 1) * x) ^
            ((y >> 1 & 1) * Xtime(x)) ^
            ((y >> 2 & 1) * Xtime(Xtime(x))) ^
            ((y >> 3 & 1) * Xtime(Xtime(Xtime(x)))) ^
            ((y >> 4 & 1) * Xtime(Xtime(Xtime(Xtime(x))))));
}
#else
#define Multiply(x, y)                                \
	(((y & 1) * x) ^ \
	((y >> 1 & 1) * Xtime(x)) ^ \
	((y >> 2 & 1) * Xtime(Xtime(x))) ^ \
	((y >> 3 & 1) * Xtime(Xtime(Xtime(x)))) ^ \
	((y >> 4 & 1) * Xtime(Xtime(Xtime(Xtime(x))))))   \

#endif

/* MixColumns function mixes the columns of the state matrix.                        */
/* The method used to multiply may be difficult to understand for the inexperienced. */
/* Please use the references to gain more information.                               */
static void InvMixColumns(void)
{
    int i;
    uint8_t u8a, u8b, u8c, u8d;
    for (i = 0; i<4; ++i)
    {
        u8a = (*s_pu8State)[i][0];
        u8b = (*s_pu8State)[i][1];
        u8c = (*s_pu8State)[i][2];
        u8d = (*s_pu8State)[i][3];

        (*s_pu8State)[i][0] = Multiply(u8a, 0x0e) ^ Multiply(u8b, 0x0b) ^ Multiply(u8c, 0x0d) ^ Multiply(u8d, 0x09);
        (*s_pu8State)[i][1] = Multiply(u8a, 0x09) ^ Multiply(u8b, 0x0e) ^ Multiply(u8c, 0x0b) ^ Multiply(u8d, 0x0d);
        (*s_pu8State)[i][2] = Multiply(u8a, 0x0d) ^ Multiply(u8b, 0x09) ^ Multiply(u8c, 0x0e) ^ Multiply(u8d, 0x0b);
        (*s_pu8State)[i][3] = Multiply(u8a, 0x0b) ^ Multiply(u8b, 0x0d) ^ Multiply(u8c, 0x09) ^ Multiply(u8d, 0x0e);
    }
}


/* The SubBytes Function Substitutes the values in the   */
/* state matrix with values in an S-box.                 */
static void InvSubBytes(void)
{
    uint8_t i, j;
    for (i = 0; i<4; ++i)
    {
        for (j = 0; j<4; ++j)
        {
            (*s_pu8State)[j][i] = GetSBoxInvert((*s_pu8State)[j][i]);
        }
    }
}

static void InvShiftRows(void)
{
    uint8_t u8Temp;

    /* Rotate first row 1 columns to right */
    u8Temp = (*s_pu8State)[3][1];
    (*s_pu8State)[3][1] = (*s_pu8State)[2][1];
    (*s_pu8State)[2][1] = (*s_pu8State)[1][1];
    (*s_pu8State)[1][1] = (*s_pu8State)[0][1];
    (*s_pu8State)[0][1] = u8Temp;

    /*  Rotate second row 2 columns to right */
    u8Temp = (*s_pu8State)[0][2];
    (*s_pu8State)[0][2] = (*s_pu8State)[2][2];
    (*s_pu8State)[2][2] = u8Temp;

    u8Temp = (*s_pu8State)[1][2];
    (*s_pu8State)[1][2] = (*s_pu8State)[3][2];
    (*s_pu8State)[3][2] = u8Temp;

    /* Rotate third row 3 columns to right */
    u8Temp = (*s_pu8State)[0][3];
    (*s_pu8State)[0][3] = (*s_pu8State)[1][3];
    (*s_pu8State)[1][3] = (*s_pu8State)[2][3];
    (*s_pu8State)[2][3] = (*s_pu8State)[3][3];
    (*s_pu8State)[3][3] = u8Temp;
}


/* Cipher is the main function that encrypts the PlainText. */
static void Cipher(void)
{
    uint8_t u8Round = 0;

    /* Add the First round key to the state before starting the rounds. */
    AddRoundKey(0);

    /* There will be Nr rounds.                           */
    /* The first Nr-1 rounds are identical.               */
    /* These Nr-1 rounds are executed in the loop below.  */
    for (u8Round = 1; u8Round < NR; ++u8Round)
    {
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(u8Round);
    }

    /* The last round is given below.                         */
    /* The MixColumns function is not here in the last round. */
    SubBytes();
    ShiftRows();
    AddRoundKey(NR);
}

static void InvCipher(void)
{
    uint8_t u8Round = 0;

    /* Add the First round key to the state before starting the rounds. */
    AddRoundKey(NR);

    /* There will be Nr rounds.                          */
    /* The first Nr-1 rounds are identical.              */
    /* These Nr-1 rounds are executed in the loop below. */
    for (u8Round = NR - 1; u8Round>0; u8Round--)
    {
        InvShiftRows();
        InvSubBytes();
        AddRoundKey(u8Round);
        InvMixColumns();
    }

    /* The last round is given below.                         */
    /* The MixColumns function is not here in the last round. */
    InvShiftRows();
    InvSubBytes();
    AddRoundKey(0);
}

static void BlockCopy(uint8_t* pu8Output, uint8_t* pu8Input)
{
    uint8_t i;
    for (i = 0; i<KEYLEN; ++i)
    {
        pu8Output[i] = pu8Input[i];
    }
}



/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/

void AES128_ECB_encrypt(uint8_t* pu8Input, const uint8_t* pu8Key, uint8_t* pu8Output)
{
    /* Copy input to output, and work in-memory on output */
    BlockCopy(pu8Output, pu8Input);
    s_pu8State = (sState_t*)pu8Output;

    s_pu8Key = pu8Key;
    KeyExpansion();

    /* The next function call encrypts the PlainText with the Key using AES algorithm. */
    Cipher();
}

void AES128_ECB_decrypt(uint8_t* pu8Input, const uint8_t* pu8Key, uint8_t *pu8Output)
{
    /* Copy input to output, and work in-memory on output */
    BlockCopy(pu8Output, pu8Input);
    s_pu8State = (sState_t*)pu8Output;

    /* The KeyExpansion routine must be called before encryption. */
    s_pu8Key = pu8Key;
    KeyExpansion();

    InvCipher();
}


static void XorWithIv(uint8_t* pu8Buf)
{
    uint8_t i;
    for (i = 0; i < KEYLEN; ++i)
    {
        pu8Buf[i] ^= s_pu8Iv[i];
    }
}

void AES128_CBC_encrypt_buffer(uint8_t* pu8Output, uint8_t* pu8Input, uint32_t u32Length, const uint8_t* pu8Key, const uint8_t* pu8Iv)
{
    uintptr_t i;
    uint8_t remainders = u32Length % KEYLEN; /* Remaining bytes in the last non-full block */

    BlockCopy(pu8Output, pu8Input);
    s_pu8State = (sState_t*)pu8Output;

    /* Skip the key expansion if key is passed as 0 */
    if (0 != pu8Key)
    {
        s_pu8Key = pu8Key;
        KeyExpansion();
    }

    if (pu8Iv != 0)
    {
        s_pu8Iv = (uint8_t*)pu8Iv;
    }

    for (i = 0; i < u32Length; i += KEYLEN)
    {
        XorWithIv(pu8Input);
        BlockCopy(pu8Output, pu8Input);
        s_pu8State = (sState_t*)pu8Output;
        Cipher();
        s_pu8Iv = pu8Output;
        pu8Input += KEYLEN;
        pu8Output += KEYLEN;
    }

    if (remainders)
    {
        BlockCopy(pu8Output, pu8Input);
        memset(pu8Output + remainders, 0, KEYLEN - remainders); /* add 0-padding */
        s_pu8State = (sState_t*)pu8Output;
        Cipher();
    }
}

void AES128_CBC_decrypt_buffer(uint8_t* pu8Output, uint8_t* pu8Input, uint32_t u32Length, const uint8_t* pu8Key, const uint8_t* pu8Iv)
{
    uintptr_t i;
    uint8_t remainders = u32Length % KEYLEN; /* Remaining bytes in the last non-full block */

    BlockCopy(pu8Output, pu8Input);
    s_pu8State = (sState_t*)pu8Output;

    /* Skip the key expansion if key is passed as 0 */
    if (0 != pu8Key)
    {
        s_pu8Key = pu8Key;
        KeyExpansion();
    }

    /* If iv is passed as 0, we continue to encrypt without re-setting the Iv */
    if (pu8Iv != 0)
    {
        s_pu8Iv = (uint8_t*)pu8Iv;
    }

    for (i = 0; i < u32Length; i += KEYLEN)
    {
        BlockCopy(pu8Output, pu8Input);
        s_pu8State = (sState_t*)pu8Output;
        InvCipher();
        XorWithIv(pu8Output);
        s_pu8Iv = pu8Input;
        pu8Input += KEYLEN;
        pu8Output += KEYLEN;
    }

    if (remainders)
    {
        BlockCopy(pu8Output, pu8Input);
        memset(pu8Output + remainders, 0, KEYLEN - remainders); /* add 0-padding */
        s_pu8State = (sState_t*)pu8Output;
        InvCipher();
    }
}

/* prints string as hex */
void Phex(uint8_t* pu8Str)
{
    unsigned char i;
    for (i = 0; i < 16; ++i)
        printf("%.2x", pu8Str[i]);
    printf("\n");
}

void TestEncryptEcbVerbose(void)
{
    /* Example of more verbose verification */

    uint8_t i, au8Buf[64], au8Buf2[64];

    /* 128bit key */
    uint8_t au8Key[16] = { (uint8_t)0x2b, (uint8_t)0x7e, (uint8_t)0x15, (uint8_t)0x16, (uint8_t)0x28, (uint8_t)0xae, (uint8_t)0xd2, (uint8_t)0xa6, (uint8_t)0xab, (uint8_t)0xf7, (uint8_t)0x15, (uint8_t)0x88, (uint8_t)0x09, (uint8_t)0xcf, (uint8_t)0x4f, (uint8_t)0x3c };
    /* 512bit text */
    uint8_t au8PlainText[64] = { (uint8_t)0x6b, (uint8_t)0xc1, (uint8_t)0xbe, (uint8_t)0xe2, (uint8_t)0x2e, (uint8_t)0x40, (uint8_t)0x9f, (uint8_t)0x96, (uint8_t)0xe9, (uint8_t)0x3d, (uint8_t)0x7e, (uint8_t)0x11, (uint8_t)0x73, (uint8_t)0x93, (uint8_t)0x17, (uint8_t)0x2a,
                                 (uint8_t)0xae, (uint8_t)0x2d, (uint8_t)0x8a, (uint8_t)0x57, (uint8_t)0x1e, (uint8_t)0x03, (uint8_t)0xac, (uint8_t)0x9c, (uint8_t)0x9e, (uint8_t)0xb7, (uint8_t)0x6f, (uint8_t)0xac, (uint8_t)0x45, (uint8_t)0xaf, (uint8_t)0x8e, (uint8_t)0x51,
                                 (uint8_t)0x30, (uint8_t)0xc8, (uint8_t)0x1c, (uint8_t)0x46, (uint8_t)0xa3, (uint8_t)0x5c, (uint8_t)0xe4, (uint8_t)0x11, (uint8_t)0xe5, (uint8_t)0xfb, (uint8_t)0xc1, (uint8_t)0x19, (uint8_t)0x1a, (uint8_t)0x0a, (uint8_t)0x52, (uint8_t)0xef,
                                 (uint8_t)0xf6, (uint8_t)0x9f, (uint8_t)0x24, (uint8_t)0x45, (uint8_t)0xdf, (uint8_t)0x4f, (uint8_t)0x9b, (uint8_t)0x17, (uint8_t)0xad, (uint8_t)0x2b, (uint8_t)0x41, (uint8_t)0x7b, (uint8_t)0xe6, (uint8_t)0x6c, (uint8_t)0x37, (uint8_t)0x10
                               };

    memset(au8Buf, 0, 64);
    memset(au8Buf2, 0, 64);

    /* print text to encrypt, key and IV */
    printf("ECB encrypt verbose:\n\n");
    printf("plain text:\n");
    for (i = (uint8_t)0; i < (uint8_t)4; ++i)
    {
        Phex(au8PlainText + i * (uint8_t)16);
    }
    printf("\n");

    printf("key:\n");
    Phex(au8Key);
    printf("\n");

    /* print the resulting cipher as 4 x 16 byte strings */
    printf("ciphertext:\n");
    for (i = 0; i < 4; ++i)
    {
        AES128_ECB_encrypt(au8PlainText + (i * 16), au8Key, au8Buf + (i * 16));
        Phex(au8Buf + (i * 16));
    }
    printf("\n");
}


void TestEncryptEcb(void)
{
    uint8_t au8Key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t au8In[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    uint8_t au8Out[] = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
    uint8_t au8Buffer[16];

 uint32_t u32AES128_ECB_encrypt32Time;
         /* These sections are for software CRC-32 */
    TIMER0->CMP = 0xFFFFFF; // Reload TCMPR to restart Timer0 counting from TDR = 0
	
	

    AES128_ECB_encrypt(au8In, au8Key, au8Buffer);
    u32AES128_ECB_encrypt32Time = TIMER0->CNT;
    printf("ECB encrypt TIME generate time result: %d us.\n", u32AES128_ECB_encrypt32Time);
    
    printf("ECB encrypt: ");

    if (0 == memcmp((char*)au8Out, (char*)au8Buffer, 16))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}

void TestDecryptCbc(void)
{
    /* Example "simulating" a smaller buffer... */

    uint8_t au8Key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t au8Iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t au8In[] = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                        0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                        0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
                      };
    uint8_t au8Out[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                         0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                         0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                         0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
                       };
    uint8_t au8Buffer[64];

    uint32_t u32AES128_CBC_decrypt32Time;
         /* These sections are for software CRC-32 */
    TIMER0->CMP = 0xFFFFFF; // Reload TCMPR to restart Timer0 counting from TDR = 0
	
    AES128_CBC_decrypt_buffer(au8Buffer + 0, au8In + 0, 16, au8Key, au8Iv);
    AES128_CBC_decrypt_buffer(au8Buffer + 16, au8In + 16, 16, 0, 0);
    AES128_CBC_decrypt_buffer(au8Buffer + 32, au8In + 32, 16, 0, 0);
    AES128_CBC_decrypt_buffer(au8Buffer + 48, au8In + 48, 16, 0, 0);
    u32AES128_CBC_decrypt32Time = TIMER0->CNT;
											 
    printf("CBC decrypt TIME:%d us\n\r",u32AES128_CBC_decrypt32Time);
    printf("CBC decrypt: ");

    if (0 == memcmp((char*)au8Out, (char*)au8Buffer, 64))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}

void TestEncryptCbc(void)
{
	
    uint8_t au8Key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t au8Iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t au8In[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
                      };
    uint8_t au8Out[] = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                         0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                         0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                         0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
                       };
    uint8_t au8Buffer[64];

    uint32_t u32AES128_CBEncrypt32Time;
         /* These sections are for software CRC-32 */
    TIMER0->CMP = 0xFFFFFF; // Reload TCMPR to restart Timer0 counting from TDR = 0
	
	

    AES128_CBC_encrypt_buffer(au8Buffer, au8In, 64, au8Key, au8Iv);
    u32AES128_CBEncrypt32Time = TIMER0->CNT;
    printf("CBC encrypt TIME generate time result: %d us.\n", u32AES128_CBEncrypt32Time);
    printf("\n");
    

    printf("CBC encrypt: ");

    if (0 == memcmp((char*)au8Out, (char*)au8Buffer, 64))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}


void TestDecryptEcb(void)
{
    uint8_t au8Key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t au8In[]  = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
    uint8_t au8Out[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    uint8_t au8Buffer[16];

  uint32_t u32AES128_ECB_decrypt32Time;
         /* These sections are for software CRC-32 */
    TIMER0->CMP = 0xFFFFFF; // Reload TCMPR to restart Timer0 counting from TDR = 0
	
	

    AES128_ECB_decrypt(au8In, au8Key, au8Buffer);
    u32AES128_ECB_decrypt32Time = TIMER0->CNT;
    printf("ECB encrypt TIME generate time result: %d us.\n", u32AES128_ECB_decrypt32Time);

    printf("ECB decrypt: ");

    if (0 == memcmp((char*)au8Out, (char*)au8Buffer, 16))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}






void AES_test(void)
{

   	  /* Open and start Timer0 counting in Periodic mode and one tick is 1 us. */
    TIMER_Open(TIMER0, TIMER_PERIODIC_MODE, 1000000);

    /* Start Timer 0 */
    TIMER_Start(TIMER0);
    

    TestEncryptCbc();
    TestDecryptCbc();
	    TestDecryptEcb();
   	TestEncryptEcb();

    

    while(1);
}

/*** (C) COPYRIGHT 2019 Nuvoton Technology Corp. ***/

