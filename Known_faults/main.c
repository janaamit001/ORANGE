#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <fcntl.h>  


#include "crypto_aead.h"
#include "api.h"
//#include "photon.h"

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

#define MAX_FILE_NAME				256
#define MAX_MESSAGE_LENGTH			32
#define MAX_ASSOCIATED_DATA_LENGTH	32

#define number 2
#define sboxSize 16

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long ul;


extern unsigned char st[32], tg[16], ftag[ 16 ], nfstate[32], fstate[32];

unsigned char s[16] = {0xc, 5, 6, 0xb, 9, 0, 0xa, 0xd, 3, 0xe, 0xf, 8, 4, 7, 1, 2};

clock_t start, end;
double cpu_time_used;


const unsigned char ReductionPoly1 = 0x3;
const unsigned char WORDFILTER1 = ((unsigned char) 1<<4)-1;


const unsigned char MixColMatrix1[8][8] = {{ 2,  4,  2, 11,  2,  8,  5,  6},
    {12,  9,  8, 13,  7,  7,  5,  2},
    { 4,  4, 13, 13,  9,  4, 13,  9},
    { 1,  6,  5,  1, 12, 13, 15, 14},
    {15, 12,  9, 13, 14,  5, 14, 13},
    { 9, 14,  5, 15,  4, 12,  9,  6},
    {12,  2,  2, 10,  3,  1,  1, 14},
    {15,  1, 13, 10,  5, 10,  2,  3}};
    
const unsigned char invMixColMatrix1[8][8] = {
				{4, 7, 9, 10, 12, 12, 3, 15},
				{13, 13, 10, 10, 7, 13, 10, 7},
				{14, 2, 3, 14, 4, 10, 5, 11},
				{5, 4, 7, 10, 11, 3, 11, 10},
				{7, 11, 3, 5, 13, 4, 7, 2},
				{4, 15, 15, 6, 1, 14, 14, 11},
				{5, 14, 10, 6, 3, 6, 15, 1},
				{2, 1, 12, 1, 4, 11, 3, 9}
};


void init_buffer(unsigned char *buffer, unsigned long long numbytes);

void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length);

int generate_test_vectors();

void print_bstr(const char *label, const unsigned char *data, unsigned long long length)
{    
    printf("%s", label);
        
	for (unsigned long long i = 0; i < length; i++)
		printf("%02X ", data[i]);
	    
    printf("\n\n");
}

void print_tag(const char *label, const unsigned char *data, unsigned long long length, unsigned long long length1)
{    
    printf("%s", label);
        
	for (unsigned long long i = length; i < length+length1; i++)
		printf("%02X ", data[i]);
	    
    printf("\n\n");
}


int main()
{

	start = clock();
	int ret = generate_test_vectors();

	if (ret != KAT_SUCCESS) {
		 printf("test vector generation failed with code %d\n", ret);
	}

	return ret;
}


void copy_ciphertext( unsigned char ct1[], unsigned char ct[] ) {

	for( short i = 0; i < (MAX_MESSAGE_LENGTH + CRYPTO_ABYTES); ++i )
		ct1[ i ] = ct[ i ];

	return;
}

void xor_of_diff_tag( unsigned char *st, unsigned char ct1[] ) {

	/*uint8_t byte[ 16 ];
	short i, j, counter = 0;
	
	for( i = 0; i < 4; ++i ) {
	
		for( j = 0; j < 4; ++j ) {
		
			//byte[ counter ] = (( state[ i ][ j ] << 4 ) & 0xf0 ) ^ ( state[ i ][ j + 1 ] & 0x0f );
			byte[i*4+j]  = state[i][j*2  ] << 4;
			byte[i*4+j] |= state[i][j*2+1];
		}
	}*/
	
	//counter = 0;
	for( int i = MAX_MESSAGE_LENGTH; i < (MAX_MESSAGE_LENGTH + CRYPTO_ABYTES); ++i ) {
	
		ct1[ i ] ^= st[ i-MAX_MESSAGE_LENGTH ];
		//++counter;
	}

	return;
}

unsigned char FieldMult1(unsigned char a, unsigned char b)
{
    unsigned char x = a, ret = 0;
    unsigned int i;
    for(i = 0; i < 4; i++) {
        if((b>>i)&1) ret ^= x;
        if((x>>3)&1) {
            x <<= 1;
            x ^= ReductionPoly1;
        }
        else x <<= 1;
    }
    return ret&WORDFILTER1;
}


    
//The function to store four characters to unsigned u32//
void store321(u8 *Bytes, u32 word)
{ int i;
    for (i = 0 ; i < 4 ; i++) {Bytes[3-i] = (u8)word;  word >>= 8; }
}



//The function to load a u32 to 4 byte array//
u32 load321(u8* Bytes)
{int i; u32 Block;
    Block=0;
    //Block = (u32)(Bytes[3]);
    for(i = 0; i < 4; i++) {Block <<= 8; Block = (Block)^(u32)(Bytes[i]);}
    return Block;}

void ShiftRow1(u8* State)
{
    u32 i;
    
    for(i = 0 ; i < 8 ; i++)
    {
        store321(State+4*i, (((load321(State+4*i))<<4*i)|((load321(State+4*i))>>((32-4*i)%32))));
    }
    
    return;
}


void invShiftRow1(u8* State)
{
    u32 i;
    
    for(i = 0 ; i < 8 ; i++)
    {
        store321(State+4*i, (((load321(State+4*i))>>4*i)|((load321(State+4*i))<<((32-4*i)%32))));
    }
    
    return;
}



unsigned char TwoColMult1(unsigned char a0, unsigned char a1, unsigned char a2, unsigned char a3, unsigned char a4, unsigned char a5, unsigned char a6, unsigned char a7, unsigned int index)
{
    return (FieldMult1((a0&15), MixColMatrix1[index][0])^ (FieldMult1((a0>>4), MixColMatrix1[index][0])<<4) ^ FieldMult1((a1&15), MixColMatrix1[index][1])^ (FieldMult1((a1>>4), MixColMatrix1[index][1])<<4) ^ FieldMult1((a2&15), MixColMatrix1[index][2])^ (FieldMult1((a2>>4), MixColMatrix1[index][2])<<4) ^ FieldMult1((a3&15), MixColMatrix1[index][3])^ (FieldMult1((a3>>4), MixColMatrix1[index][3])<<4) ^ FieldMult1((a4&15), MixColMatrix1[index][4])^ (FieldMult1((a4>>4), MixColMatrix1[index][4])<<4) ^ FieldMult1((a5&15), MixColMatrix1[index][5])^ (FieldMult1((a5>>4), MixColMatrix1[index][5])<<4)^ FieldMult1((a6&15), MixColMatrix1[index][6])^ (FieldMult1((a6>>4), MixColMatrix1[index][6])<<4)^ FieldMult1((a7&15), MixColMatrix1[index][7])^ (FieldMult1((a7>>4), MixColMatrix1[index][7])<<4));
    
    
}


unsigned char invTwoColMult1(unsigned char a0, unsigned char a1, unsigned char a2, unsigned char a3, unsigned char a4, unsigned char a5, unsigned char a6, unsigned char a7, unsigned int index)
{
    return (FieldMult1((a0&15), invMixColMatrix1[index][0])^ (FieldMult1((a0>>4), invMixColMatrix1[index][0])<<4) ^ FieldMult1((a1&15), invMixColMatrix1[index][1])^ (FieldMult1((a1>>4), invMixColMatrix1[index][1])<<4) ^ FieldMult1((a2&15), invMixColMatrix1[index][2])^ (FieldMult1((a2>>4), invMixColMatrix1[index][2])<<4) ^ FieldMult1((a3&15), invMixColMatrix1[index][3])^ (FieldMult1((a3>>4), invMixColMatrix1[index][3])<<4) ^ FieldMult1((a4&15), invMixColMatrix1[index][4])^ (FieldMult1((a4>>4), invMixColMatrix1[index][4])<<4) ^ FieldMult1((a5&15), invMixColMatrix1[index][5])^ (FieldMult1((a5>>4), invMixColMatrix1[index][5])<<4)^ FieldMult1((a6&15), invMixColMatrix1[index][6])^ (FieldMult1((a6>>4), invMixColMatrix1[index][6])<<4)^ FieldMult1((a7&15), invMixColMatrix1[index][7])^ (FieldMult1((a7>>4), invMixColMatrix1[index][7])<<4));
    
    
}




void MixColumn1(unsigned char *State)
{
    unsigned int j;
    unsigned char a0, a1, a2, a3, a4, a5, a6, a7;
    
    for(j = 0 ; j < 4 ; j++)
    {
        a0 =  TwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 0);
        
        a1 =  TwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 1);
        
        a2 =  TwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 2);
        
        a3 =  TwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 3);
        
        a4 =  TwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 4);
        
        a5 =  TwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 5);
        
        a6 =  TwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 6);
        
        a7 =  TwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 7);
        
        State[j] = a0;
        State[4+j] = a1;
        State[8+j] = a2;
        State[12+j] = a3;
        State[16+j] = a4;
        State[20+j] = a5;
        State[24+j] = a6;
        State[28+j] = a7;
        
        
    }
    return;
}





void invMixColumn1(unsigned char *State)
{
    unsigned int j;
    unsigned char a0, a1, a2, a3, a4, a5, a6, a7;
    
    for(j = 0 ; j < 4 ; j++)
    {
        a0 =  invTwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 0);
        
        a1 =  invTwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 1);
        
        a2 =  invTwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 2);
        
        a3 =  invTwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 3);
        
        a4 =  invTwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 4);
        
        a5 =  invTwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 5);
        
        a6 =  invTwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 6);
        
        a7 =  invTwoColMult1(State[0+j], State[4+j], State[8+j], State[12+j], State[16+j], State[20+j], State[24+j], State[28+j], 7);
        
        State[j] = a0;
        State[4+j] = a1;
        State[8+j] = a2;
        State[12+j] = a3;
        State[16+j] = a4;
        State[20+j] = a5;
        State[24+j] = a6;
        State[28+j] = a7;
        
        
    }
    return;
}



unsigned char **diffDistribution(unsigned char s[sboxSize]) {

	int i; 
	int x, y, delta, delta1;
	
	unsigned char** count = malloc(sboxSize*sizeof(int *));
	
	for(i = 0; i < sboxSize; ++i) {
		
		count[i] = malloc(sboxSize*sizeof(int));
		memset(count[i],0,sboxSize*sizeof(int));
	}
		
	for(y = 0; y < sboxSize; ++y) {
		
		for(x = 0; x < sboxSize; ++x) {
			
			delta = y^x;
			delta1 = s[x]^s[y];
			count[delta][delta1]++;
		}		
	}
	
	return count;
}


void Recover_state_columnwise( unsigned char known_diff, unsigned char pos, unsigned char count, unsigned char **ptr ) {

	unsigned char nfst[ 32], fst[ 32], temp[ 32], col[ 32 ];
	FILE *f0, *f1, *f2, *f3, *f4, *f5, *f6, *f7;
	unsigned char diff[ 8 ], diff1[ 8 ], delta, filename[ 24 ];
	unsigned char i, j;
	time_t t;

	srand( (unsigned) time( &t ) );

	for (i = 0; i < 32; i++)
	{
		nfst[i ] = nfstate[i ];
		fst[i ] = fstate[i ];
	}
	
	for( i = 0; i < 32; ++i ) {
	
		temp[ i ] = nfst[ i ] ^ fst[ i ];
	}
	
	
	
	
	//print_state(nfst);
	//print_state(fst);
	
	//print_state(temp);
	printf("Full state difference::\n");
	for( short i = 0; i < 32; ++i ) {
	
		printf("%x ", temp[ i ] );
		
	}
	
	printf("\n");
	
	invMixColumn1( temp );
	//print_state( temp );
	invShiftRow1( temp );
	//print_state( temp );
	
	printf("///////////////Full state difference::\n");
	for( short i = 0; i < 32; ++i ) {
	
		printf("%x ", temp[ i ] );
		
	}
	
	printf("\n");
	
	printf("Right hand diff:\n");
	if((pos%8)%2 == 0) {
	
		diff[ 0 ] = temp[ 4*(pos/8) + (pos%8)/2 ] >> 4;
		known_diff = (known_diff >> 4);
	}
	else {
		diff[ 0 ] = temp[ 4*(pos/8) + (pos%8)/2 ] & 0x0f;
	}
	
	printf("\n");
	
	printf("Right hand diff:diff = %x, fault = %x\n", diff[0], known_diff);
		
	sprintf(filename, "key_column_%d,%d,%d.txt", 4*(pos/8),(pos%8), count);
	if ((f0 = fopen(filename, "w+")) == NULL) {
		fprintf(stderr, "Couldn't open <%s> for write\n", filename);
		exit(1);
	}
	for( i = 0; i < 16; ++i ) {
	
		
		//printf("0-> %x %x %x\n", i, s[ i ] ^ s[ i ^ diff1[ 0 ] ], diff[ 0 ]);
		if( ( s[ i ] ^ s[ i ^ known_diff ] ) == diff[ 0 ] ) {
			
			printf("f0:: i = %x, diff = %x\n", i, diff[ 0 ]);
			fprint_bstr(f0, "", &i, 1);
		}
		
	}
	
	fclose( f0 );
		
	return;
}


unsigned short findMax( unsigned short arr[] ) {

	unsigned short max = 0;

	for( unsigned char i = 0; i < 16; ++i ) {
	
		if( max < arr[ i ] )
			max = arr[ i ];
	}

	return( max );
}


void state_nibble( unsigned char pos, unsigned char value ) {

	FILE *fp1; 
	unsigned char val;
	unsigned short max, arr[ 16 ] = {0};
	unsigned short num = 0, count1 = 0;
	unsigned char filename[ 24 ];

	//int number = 8;
	//printf("State[%d]\n");
	
	printf("count = %d, ", value);
	for( unsigned char count = 1; count <= value; ++count ) {
	
		sprintf(filename, "key_column_%d,%d,%d.txt", 4*(pos/8),(pos%8),count);
		if ((fp1 = fopen(filename, "r+")) == NULL) {
			fprintf(stderr, "Couldn't open <%s> for read\n", filename);
			exit(1);
		}
		fseek(fp1, 0, SEEK_SET);
		while(fread(&val, 1, 1, fp1) == 1) {
		

			//printf ("val = %c", val);
			if( ( val == 'a' ) || ( val == 'b' ) || ( val == 'c' ) || ( val == 'd' ) || ( val == 'e' ) || ( val == 'f' ) )
				val = val - 97 + 10;
			else 
				val = val - 48;
				
			//printf ("......val = %x\n", val);
			
			arr[ val ] += 1;
		}
		//printf("\n");
		fclose( fp1 );
	}
	printf("Recovered nibble value at (%d,%d)-th position of the state::\n", pos/8, pos%8);
	printf("{ ");

	max = findMax( arr );
	printf("max = %d:: ", max);
	for( unsigned char i = 0; i < 16; ++i ) {

		if( arr[ i ] == max ) {
		
			printf("%x ", i );
			//printf("1st column = %04x\n", i);
			//++count1;
		}
	}
	printf("}\n\n");
	
	return;
}





int generate_test_vectors()
{
	FILE                *fp;
	char                fileName[MAX_FILE_NAME];
	unsigned char       key[CRYPTO_KEYBYTES];
	unsigned char		nonce[CRYPTO_NPUBBYTES];
	unsigned char       msg[MAX_MESSAGE_LENGTH];
	unsigned char       msg2[MAX_MESSAGE_LENGTH];
	unsigned char		ad[MAX_ASSOCIATED_DATA_LENGTH];
	unsigned char		ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
	unsigned char		ct1[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
	unsigned long long  clen, mlen2, mlen, adlen;
	unsigned int                 count = 0, total_count = 0;
	int                 func_ret, ret_val = KAT_SUCCESS;
	unsigned char **ddt = diffDistribution(s);
	
	unsigned char fault, fault1, diff, pos;
	unsigned char st_diff[32] = {0};

	init_buffer(key, sizeof(key));
	init_buffer(nonce, sizeof(nonce));
	init_buffer(msg, sizeof(msg));
	init_buffer(ad, sizeof(ad));
	
	mlen = mlen2 = MAX_MESSAGE_LENGTH;
	adlen = MAX_ASSOCIATED_DATA_LENGTH;
	
	
	time_t t;
	srand( (unsigned) time( &t ) );


	printf("Count = %d\n", count);

	print_bstr("Key = ", key, CRYPTO_KEYBYTES);

	print_bstr("Nonce = ", nonce, CRYPTO_NPUBBYTES);

	print_bstr("PT = ", msg, mlen);

	print_bstr("AD = ", ad, adlen);

	if (crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key) != 0) {
		printf("crypto_aead_encrypt returned <%d>\n", func_ret);
		ret_val = KAT_CRYPTO_FAILURE;
		return 0;
	}
	
	else
		print_tag("TAG = ", ct, mlen, CRYPTO_ABYTES);

	print_bstr("CT = ", ct, clen);

	printf("\n");

	if (crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key) != 0) {
		printf("crypto_aead_decrypt returned <%d>\n", func_ret);
		ret_val = KAT_CRYPTO_FAILURE;
		return 0;
	}
	else
		printf("Decryption is successful\n");
	
	for( pos = 0; pos < 64; ++pos ) {	
	
		//fault = ((rand()%256) & 0xf0);
		printf("\n\n..........................Position = %d\n\n", pos);
		if((pos%8)%2 == 0) {
			fault = (rand()%256 & 0xf0);
			while(fault == 0)
				fault = (rand()%256 & 0xf0);
			//fault = (fault << 4);
			//printf("if loop\n");
		}
		else {
			fault = ((rand()%256) & 0x0f);
			while(fault == 0)
				fault = ((rand()%256) & 0x0f);
		}
		//diff = (fault >> 4);
		printf("Faulty value is 0x%2x\n\n", fault);
		for( int i1 = 1; i1 < 16; ++i1 ) {
		
			//fault = ((rand()%256) & 0xf0);
			printf("At i1 = %d  ", i1);
			if((pos%8)%2 == 0)
				st_diff[ 4*(pos/8) + (pos%8)/2 ] = (i1 << 4);
			else
				st_diff[ 4*(pos/8) + (pos%8)/2 ] = i1;
			//st_diff[0] = (i1 << 4);
			
			/*printf("\nFull state difference::\n");
			for( int i = 0; i < 32; ++i ) {
			
				printf("0x%2x ", st_diff[ i ] );
				
			}*/
			ShiftRow1(st_diff);
			MixColumn1(st_diff);
			
			copy_ciphertext( ct1, ct );
			xor_of_diff_tag( st_diff, ct1 );
			
			//print_bstr("CT1 = ", ct1, clen);
																																																																																																																																																																																																							
			if (faulty_crypto_aead_decrypt(msg2, &mlen2, NULL, ct1, clen, ad, adlen, nonce, key, fault, pos) == 0) {
			
				printf("..............number of faulty decryption is successful at position %d:: %d \n", pos, count);
				//print_bstr("CT1 = ", ct1, clen);
				++count;
				Recover_state_columnwise( fault, pos, count, &ddt[ 0 ] );
				if((pos%8)%2 == 0) {
					fault1 = (rand()%256 & 0xf0);
					while((fault1 == 0) || (fault1 == fault))
						fault1 = (rand()%256 & 0xf0);
						
					fault = fault1;
					//fault = (fault << 4);
					//printf("if loop\n");
				}
				else {
					fault1 = ((rand()%256) & 0x0f);
					while((fault1 == 0) || (fault1 == fault))
						fault1 = ((rand()%256) & 0x0f);
					fault = fault1;
				}
				printf("Faulty value is 0x%2x\n\n", fault);
				i1 = 0;
				printf("i1 = %d\n", i1);
			}
			if(count == number)
				break;
			//else {
			
				//printf("faulty decryption is not successful:: \n");
			//}
			
			/*for( int j = 0; j < 32; ++j)
				st_diff[ j ] = 0;*/
				
			for( int i = 0; i < 32; ++i )
				st_diff[i] = 0;
		
		}
		
		//printf("........................iteration = %d\tcount = %d\n\n", itr, count);
		total_count += count;
		count = 0;
	}
	
	printf("total count = %d\n\n", total_count);
	end = clock();
	cpu_time_used = ( (double) (end-start))/CLOCKS_PER_SEC;
	printf("Average number of faulty queries to collect %d number of forgeries is %f with time taken = %f\n\n", number, total_count/(double)pos, cpu_time_used/(double)pos);
	
	printf("faulty tag::\n");
	print_bstr("ct = ", ct1, clen);
	printf("Actual TAG DIFFERENCES:\n");
	for( int i = 0; i < 16; ++i ) 
		printf("%x, ", ftag[i]^tg[i]);
		
	printf("\nActual state values before s-box\n");
	for( short i = 0; i < 32; ++i ) {
	
		//for( short j = 0; j < 8; ++j ) {
		
			//dstate[i][j] = st[ i ][ j ]^st1[ i ][ j ];
			printf("%x ", st[ i ]);
		//}
		
		//printf("\n");
	}
	
	printf("\n");
	
		
	for( unsigned char pos = 0; pos < 64; ++pos )
		state_nibble( pos, number );
}


void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length)
{    
    fprintf(fp, "%s", label);
        
	for (unsigned long long i = 0; i < length; i++)
		fprintf(fp, "%x", data[i]);
	    
    fprintf(fp, "\n");
}

void init_buffer(unsigned char *buffer, unsigned long long numbytes)
{
	for (unsigned long long i = 0; i < numbytes; i++)
		buffer[i] = (unsigned char)i;
}
