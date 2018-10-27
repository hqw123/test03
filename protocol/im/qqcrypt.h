#ifndef QQCRYPT_H
#define QQCRYPT_H
using namespace std;
class QQDecrypt{
public:
	QQDecrypt();
	~QQDecrypt();
	unsigned char* qqdecrypt( unsigned char* instr, int instrlen, unsigned char* key);
	int getPlainlen(unsigned char* instr, int instrlen, unsigned char* key);
private:
	void decipher(unsigned int *const v, const unsigned int *const k, 
			unsigned int *const w);
private:

};

#endif 
