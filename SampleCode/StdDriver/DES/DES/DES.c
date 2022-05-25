/******************************************************************************
 * @file     main.c
 * @brief
 *           Show how to implement software DES.
 * @note
 * Copyright (C) 2019 Nuvoton Technology Corp. All rights reserved.
 ******************************************************************************/
#include <stdio.h>
#include "NuMicro.h"


/*--------------------------------------------------------------------------*/
/* Global variables                                                         */
/*--------------------------------------------------------------------------*/
static uint8_t s_au8SubKey[16][48] = { 0 };
char g_acMyKey[8] = { 0x1,0x2,0x3,0x4,0x5,0x6,0x08 };
char g_acMyMessage[8] = { 'H','E','L','L','O','!'};
char g_acExtMessage[8];
char g_acMessageHex[16] = { 0 };

/* Initial Permutation Table */
const char g_acIPTable[64] = {
    58,50,42,34,26,18,10, 2,60,52,44,36,28,20,12, 4,
    62,54,46,38,30,22,14, 6,64,56,48,40,32,24,16, 8,
    57,49,41,33,25,17, 9, 1,59,51,43,35,27,19,11, 3,
    61,53,45,37,29,21,13, 5,63,55,47,39,31,23,15, 7
};

/* Inverse Initial Permutation Table */
const char g_acIPRTable[64] = {
    40, 8,48,16,56,24,64,32,39, 7,47,15,55,23,63,31,
    38, 6,46,14,54,22,62,30,37, 5,45,13,53,21,61,29,
    36, 4,44,12,52,20,60,28,35, 3,43,11,51,19,59,27,
    34, 2,42,10,50,18,58,26,33, 1,41, 9,49,17,57,25
};

/* Expansion Table */
static char s_acETable[48] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32, 1
};

/* PC1_Table */
static char s_acPC1Table[56] = {
    57,49,41,33,25,17, 9, 1,58,50,42,34,26,18,
    10, 2,59,51,43,35,27,19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14, 6,61,53,45,37,29,21,13, 5,28,20,12, 4
};

/* PC2_Table */
static char s_acPC2Table[48] = {
    14,17,11,24, 1, 5, 3,28,15, 6,21,10,
    23,19,12, 4,26, 8,16, 7,27,20,13, 2,
    41,52,31,37,47,55,30,40,51,34,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32
};
/* Move_Table */
static char s_acMoveTable[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

/* Substitution Box */
static char s_acSBox[8][4][16] = {
    /* S1 */
    14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7,
    0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8,
    4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0,
    15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13,
    /* S2 */
    15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
    3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
    0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
    13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9,
    /* S3 */
    10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1,
    13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7,
    1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12,
    /* S4 */
    7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15,
    13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9,
    10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4,
    3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14,
    /* S5 */
    2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9,
    14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6,
    4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14,
    11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3,
    /* S6 */
    12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11,
    10,15, 4, 2, 7,12, 0, 5, 6, 1,13,14, 0,11, 3, 8,
    9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6,
    4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13,
    /* S7 */
    4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1,
    13, 0,11, 7, 4, 0, 1,10,14, 3, 5,12, 2,15, 8, 6,
    1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2,
    6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12,
    /* S8 */
    13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7,
    1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2,
    7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8,
    2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11
};

/* Permutation Table */
static char s_acPTable[32] = {
    16, 7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10,
    2, 8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25
};


/*---------------------------------------------------------------------------------------------------------*/
/*  Copy Bit Function                                                                                      */
/*---------------------------------------------------------------------------------------------------------*/
void BitCopy(uint8_t * pu8Data_out, uint8_t * pu8Data_in, int i8Num)
{
    int i = 0;
    for (i = 0; i<i8Num; i++)
    {
        pu8Data_out[i] = pu8Data_in[i];
    }

}

/*---------------------------------------------------------------------------------------------------------*/
/*  Change Bit Function                                                                                    */
/*---------------------------------------------------------------------------------------------------------*/
void ChangeBit(uint8_t * pu8Data_out, int i8Num)
{
    int i, j;
    static uint8_t au8Temp[8] = { 0 };
    for (i = 0; i<i8Num / 8; i++)
    {
        BitCopy(au8Temp, pu8Data_out, i8Num / 8);
        for (j = 0; j<i8Num / 8; j++)
        {
            pu8Data_out[j] = au8Temp[i8Num / 8 - 1 - j];
        }
        pu8Data_out += i8Num / 8;
    }
}

/*---------------------------------------------------------------------------------------------------------*/
/*  Convert Byte to Bit Function                                                                           */
/*---------------------------------------------------------------------------------------------------------*/
void ByteToBit(uint8_t * pu8Data_out, char * pcData_in, int i8Num)
{
    int i;
    for (i = 0; i<i8Num; i++)
    {
        pu8Data_out[i] = (pcData_in[i / 8] >> (i % 8)) & 0x01;
    }
}

/*---------------------------------------------------------------------------------------------------------*/
/*  Convert Bit to Hex Function                                                                            */
/*---------------------------------------------------------------------------------------------------------*/
void BitToHex(char * pcData_out, uint8_t * pu8Data_in, int i8Num)
{
    int i;
    for (i = 0; i<i8Num / 4; i++)
    {
        pcData_out[i] = 0;
    }
    for (i = 0; i<i8Num / 4; i++)
    {
        pcData_out[i] = pu8Data_in[4 * i] + pu8Data_in[4 * i + 1] * 2 + pu8Data_in[4 * i + 2] * 4 + pu8Data_in[4 * i + 3] * 8;
        if (pcData_out[i] % 16>9)
        {
            pcData_out[i] = pcData_out[i] % 16 + '7';
        }
        else
            pcData_out[i] = pcData_out[i] % 16 + '0';
    }
}

/*---------------------------------------------------------------------------------------------------------*/
/*  Convert Hex to Bit Function                                                                            */
/*---------------------------------------------------------------------------------------------------------*/
void HexToBit(uint8_t * pu8Data_out, char * pcData_in, int i8Num)
{
    int i;
    for (i = 0; i<i8Num; i++)
    {
        if (pcData_in[i / 4] <= '9')
        {
            pu8Data_out[i] = ((pcData_in[i / 4] - '0') >> (i % 4)) & 0x01;
        }
        else
        {
            pu8Data_out[i] = ((pcData_in[i / 4] - '7') >> (i % 4)) & 0x01;
        }
    }
}

/*---------------------------------------------------------------------------------------------------------*/
/*  Convert Bit to Byte Function                                                                           */
/*---------------------------------------------------------------------------------------------------------*/
void BitToByte(char acg_acMyMessage[8], uint8_t * pu8Message_in, int i8Num)
{
    int i = 0;
    for (i = 0; i<(i8Num / 8); i++)
    {
        acg_acMyMessage[i] = 0;
    }
    for (i = 0; i<i8Num; i++)
    {
        acg_acMyMessage[i / 8] |= pu8Message_in[i] << (i % 8);
    }
}

/*---------------------------------------------------------------------------------------------------------*/
/*  Table Replace Function                                                                                 */
/*---------------------------------------------------------------------------------------------------------*/
void TableReplace(uint8_t *pu8Data_out, uint8_t * pucData_in, const char *pcTable, int i8Num)
{
    int i = 0;
    static uint8_t au8Temp[256] = { 0 };
    for (i = 0; i<i8Num; i++)
    {
        au8Temp[i] = pucData_in[pcTable[i] - 1];
    }
    BitCopy(pu8Data_out, au8Temp, i8Num);
}

/*---------------------------------------------------------------------------------------------------------*/
/*  Loop Bit Function                                                                                      */
/*---------------------------------------------------------------------------------------------------------*/
void LoopBit(uint8_t * pu8Data_out, int i8Movstep, int i8Len)
{
    static uint8_t au8Temp[256] = { 0 };
    BitCopy(au8Temp, pu8Data_out, i8Movstep);
    BitCopy(pu8Data_out, pu8Data_out + i8Movstep, i8Len - i8Movstep);
    BitCopy(pu8Data_out + i8Len - i8Movstep, au8Temp, i8Movstep);
}

/*---------------------------------------------------------------------------------------------------------*/
/*  Xor Function:                                                                                          */
/*     DES does XOR operation on the expanded right section and the round key                              */
/*---------------------------------------------------------------------------------------------------------*/
void Xor(uint8_t * pu8Message_out, uint8_t * pu8Message_in, int i8Num)
{
    int i;
    for (i = 0; i<i8Num; i++)
    {
        pu8Message_out[i] = pu8Message_out[i] ^ pu8Message_in[i];
    }
}

/*---------------------------------------------------------------------------------------------------------*/
/*  Set DES Private Key Function                                                                           */
/*---------------------------------------------------------------------------------------------------------*/
void SetKey(char acMyKey[8])
{
    int i;
    static uint8_t au8Key_bit[64] = { 0 };
    static uint8_t *pu8Key_bit_L, *pucKey_bit_R;

    pu8Key_bit_L = &au8Key_bit[0];
    pucKey_bit_R = &au8Key_bit[28];
    ByteToBit(au8Key_bit, acMyKey, 64);

    /* Key transform: 64 bit --> 56 bit */
    TableReplace(au8Key_bit, au8Key_bit, s_acPC1Table, 56);

    /* Generate keys for 16 round DES */
    for (i = 0; i<16; i++)
    {
        /* DES rotation of left 28 bits */
        LoopBit(pu8Key_bit_L, s_acMoveTable[i], 28);

        /* DES rotation of right 28 bits */
        LoopBit(pucKey_bit_R, s_acMoveTable[i], 28);

        /* Key transform: 56 bit --> 48 bit */
        TableReplace(s_au8SubKey[i], au8Key_bit, s_acPC2Table, 48);
    }
}

/*---------------------------------------------------------------------------------------------------------*/
/*  Substitution Boxes Function                                                                            */
/*     DES uses 8 S-boxes, each with a 6-bit input and a 4-bit output.                                     */
/*---------------------------------------------------------------------------------------------------------*/
void SChange(uint8_t * pu8Data_out, uint8_t * pu8Data_in)
{
    int i;
    int r = 0, c = 0;
    for (i = 0; i<8; i++, pu8Data_in = pu8Data_in + 6, pu8Data_out = pu8Data_out + 4)
    {
        r = pu8Data_in[0] * 2 + pu8Data_in[5] * 1;
        c = pu8Data_in[1] * 8 + pu8Data_in[2] * 4 + pu8Data_in[3] * 2 + pu8Data_in[4] * 1;
        ByteToBit(pu8Data_out, &s_acSBox[i][r][c], 4);
    }
}

/*---------------------------------------------------------------------------------------------------------*/
/*  Round Function:                                                                                        */
/*      applies a 48-bit key to the rightmost 32 bits to produce a 32-bit output.                          */
/*---------------------------------------------------------------------------------------------------------*/
void FChange(uint8_t au8Data_out[32], uint8_t au8Data_in[48])
{
    static uint8_t au8Message_E[48] = { 0 };
    TableReplace(au8Message_E, au8Data_out, s_acETable, 48);
    Xor(au8Message_E, au8Data_in, 48);
    SChange(au8Data_out, au8Message_E);
    TableReplace(au8Data_out, au8Data_out, s_acPTable, 32);
}

/*---------------------------------------------------------------------------------------------------------*/
/*  DES Encrypt Function                                                                                   */
/*---------------------------------------------------------------------------------------------------------*/
void RunDesEncrypt(char acg_acMyMessage[8], char acHexMssage[16])
{
    int i;
    static uint8_t au8Message_bit[64] = { 0 };
    static uint8_t *Message_bit_L = &au8Message_bit[0], *Message_bit_R = &au8Message_bit[32];
    static uint8_t au8Temp[32] = { 0 };

    /* Convert byte message to bit */
    ByteToBit(au8Message_bit, acg_acMyMessage, 64);

    /* Data transform by IP Table*/
    TableReplace(au8Message_bit, au8Message_bit, g_acIPTable, 64);

    /* DES 16-round encryption */
    for (i = 0; i<16; i++)
    {
        BitCopy(au8Temp, Message_bit_R, 32);
        FChange(Message_bit_R, s_au8SubKey[i]);
        Xor(Message_bit_R, Message_bit_L, 32);
        BitCopy(Message_bit_L, au8Temp, 32);
    }

    /* Data transform by IPR Table*/
    TableReplace(au8Message_bit, au8Message_bit, g_acIPRTable, 64);

    /* Convert bit message to hex */
    BitToHex(acHexMssage, au8Message_bit, 64);
}

/*---------------------------------------------------------------------------------------------------------*/
/*  DES Decrypt Function                                                                                   */
/*---------------------------------------------------------------------------------------------------------*/
void RunDesDecrypt(char acg_acMyMessage[8], char acHexMessage[16])
{
    int i = 0;
    static uint8_t au8Message_bit[64] = { 0 };
    static uint8_t * Message_bit_L = &au8Message_bit[0], *Message_bit_R = &au8Message_bit[32];
    static uint8_t au8Temp[32] = { 0 };

    /* Convert hex message to bit */
    HexToBit(au8Message_bit, acHexMessage, 64);

    /* Data transform by IP Table*/
    TableReplace(au8Message_bit, au8Message_bit, g_acIPTable, 64);

    /* DES 16-round decryption */
    for (i = 15; i >= 0; i--)
    {
        BitCopy(au8Temp, Message_bit_L, 32);
        FChange(Message_bit_L, s_au8SubKey[i]);
        Xor(Message_bit_L, Message_bit_R, 32);
        BitCopy(Message_bit_R, au8Temp, 32);
    }

    /* Data transform by IPR Table*/
    TableReplace(au8Message_bit, au8Message_bit, g_acIPRTable, 64);

    /* Convert bit message to byte */
    BitToByte(acg_acMyMessage, au8Message_bit, 64);

}



/*---------------------------------------------------------------------------------------------------------*/
/*  Main Function                                                                                          */
/*---------------------------------------------------------------------------------------------------------*/
void DES_test(void)
{
uint32_t u32DESEncrypt32Time=0;
    printf("\n");
    printf("+-----------------------------------------------------------------+\n");
    printf("|  Software DES Sample Code                                 |\n");
    printf("+-----------------------------------------------------------------+\n");

	  /* Open and start Timer0 counting in Periodic mode and one tick is 1 us. */
    TIMER_Open(TIMER0, TIMER_PERIODIC_MODE, 1000000);

    /* Start Timer 0 */
    TIMER_Start(TIMER0);

     /* These sections are for software CRC-32 */
    TIMER0->CMP = 0xFFFFFF; // Reload TCMPR to restart Timer0 counting from TDR = 0
	
	
    /* key generation */
    SetKey(g_acMyKey);

    /* DES encrypt*/
    printf("DES encrypt start!\n");
	     /* These sections are for software CRC-32 */
    TIMER0->CMP = 0xFFFFFF; // Reload TCMPR to restart Timer0 counting from TDR = 0

    RunDesEncrypt(g_acMyMessage, g_acMessageHex);
		u32DESEncrypt32Time = TIMER0->CNT;
    printf("Generate time result: %d us.\n", u32DESEncrypt32Time);
    printf("\n");
    printf("DES encrypt done!\n");

    /* DES decrypt*/
    printf("DES decrypt start!\n");
		 TIMER0->CMP = 0xFFFFFF; // Reload TCMPR to restart Timer0 counting from TDR = 0
    RunDesDecrypt(g_acExtMessage, g_acMessageHex);
		u32DESEncrypt32Time = TIMER0->CNT;
    printf("Generate time result: %d us.\n", u32DESEncrypt32Time);
    printf("DES decrypt done!\n");

    printf("DES Test Done!\n");
}


/*** (C) COPYRIGHT 2019 Nuvoton Technology Corp. ***/

