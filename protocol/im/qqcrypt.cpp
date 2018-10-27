#include <iostream>
#include <string>
#include <string.h>
#include <arpa/inet.h>
#include "qqcrypt.h"
#include "util.h"

QQDecrypt::QQDecrypt(){
}
QQDecrypt::~QQDecrypt(){
}
void QQDecrypt::decipher(unsigned int *const v, const unsigned int *const k, 
			unsigned int *const w)
{
	register unsigned int
		y     = ntohl(v[0]),
		z     = ntohl(v[1]),
		a     = ntohl(k[0]),
		b     = ntohl(k[1]),
		c     = ntohl(k[2]),
		d     = ntohl(k[3]),
		n     = 0x10,
		sum   = 0xE3779B90, 
	
		delta = 0x9E3779B9;

	
	while (n-- > 0) {
		z -= ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
		y -= ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
		sum -= delta;
	}

	w[0] = htonl(y); w[1] = htonl(z);
}
int QQDecrypt::getPlainlen(unsigned char* instr, int instrlen, unsigned char* key){
	
	int count,pos;
	unsigned char decrypted[8];
	if ((instrlen % 8) || (instrlen < 16)) return 0; 

	decipher( (unsigned int *) instr, 
		(unsigned int *) key, 
		(unsigned int *) decrypted);
	pos = decrypted[0] & 0x7;
	count = instrlen - pos - 10;
	if (count < 0) return 0;
	
	return count;
}


unsigned char* QQDecrypt::qqdecrypt( unsigned char* instr, int instrlen, unsigned char* key)
{
	unsigned char 
		decrypted[8], m[8],
		* crypt_buff, 
		* crypt_buff_pre_8, 
		* outstr;
	int 
		count, 
		context_start, 
		pos, 
		padding;

#define decrypt_every_8_byte()  {\
	char bNeedRet = 0;\
	for (pos = 0; pos < 8; pos ++ ) {\
	if (context_start + pos >= instrlen) \
	{\
	bNeedRet = 1;\
	break;\
	}\
	decrypted[pos] ^= crypt_buff[pos];\
	}\
	if( !bNeedRet ) { \
	decipher( (unsigned int *) decrypted, \
	(unsigned int *) key, \
	(unsigned int *) decrypted);\
	\
	context_start +=  8;\
	crypt_buff    +=  8;\
	pos   =   0;\
	}\
}/* decrypt_every_8_byte*/
	
	
	if ((instrlen % 8) || (instrlen < 16)) return NULL; 

	decipher( (unsigned int *) instr, 
		(unsigned int *) key, 
		(unsigned int *) decrypted);
	pos = decrypted[0] & 0x7;
	count = instrlen - pos - 10;

	outstr = new unsigned char[count];
	memset(outstr,0,count);

	if (count < 0) return NULL;
	//printf("The length of plain is :\n%d\n",count);
	memset(m, 0, 8);
	crypt_buff_pre_8 = m;
	

	crypt_buff = instr + 8;
	context_start = 8;
	pos ++;
	
	padding = 1;
	while (padding <= 2) {
		if (pos < 8) {
			pos ++; padding ++;
		}
		if (pos == 8) {
			crypt_buff_pre_8 = instr;
			
			//if (! decrypt_every_8_byte()) return NULL; 
			decrypt_every_8_byte();
		}
	}
	
	
	int i=0;
	while(count !=0) {
				
		if (pos < 8) {
			
			
			outstr[i] = crypt_buff_pre_8[pos] ^ decrypted[pos];
			//*(outstr+i) = crypt_buff_pre_8[pos] ^ decrypted[pos];
			
			i ++;
			count --;
			pos ++;
			
		}
		if (pos == 8) {
			crypt_buff_pre_8 = crypt_buff - 8;
			//if (! decrypt_every_8_byte()) return NULL;
			
			decrypt_every_8_byte();
			
		}
	}
	

	for (padding = 1; padding < 8; padding ++) {
		if (pos < 8) {
			if (crypt_buff_pre_8[pos] ^ decrypted[pos]) {
				return NULL;
			}
			pos ++; 
		}
		if (pos == 8 ) {
			crypt_buff_pre_8 = crypt_buff;
			//if (! decrypt_every_8_byte()) return NULL; 
			decrypt_every_8_byte();
		}
	}
	
	return outstr;
	
}



