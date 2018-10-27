
#include "basetalkspace.h"

using namespace std;

Basetalkspace::Basetalkspace()
{
	m_tcp = NULL;
	m_http = NULL;
	objectid = 0;
	content = NULL;
	title = NULL;
	username = NULL;
	password = NULL;
	iErro = 0;

	matchtitle = pcre_compile(PATTERN_TITLE, PCRE_CASELESS, &chpError, &iErro, NULL);
	matchcontent = pcre_compile(PATTERN_CONTENT, PCRE_CASELESS, &chpError, &iErro, NULL);
}

Basetalkspace::~Basetalkspace()
{
	pcre_free(matchtitle);
	pcre_free(matchcontent);
}

int Basetalkspace::url_decode(const char *inbuf, size_t inlen, char *outbuf, size_t olen)
{
	int j = 0;
	int hex = 0; 
	for (size_t i = 0; i < inlen; ++i)
	{  
		switch (inbuf[i])  
		{
			case '+':  
				//result += ' ';  
				outbuf[j++] = ' ';
				break;  
			case '%': 
				if (isxdigit(inbuf[i + 1]) && isxdigit(inbuf[i + 2]))
				{
					//std::string hexStr = szToDecode.substr(i + 1, 2);  
					char hexStr[3] = {0};
					strncpy(hexStr, &inbuf[i + 1], 2);
					hex = strtol(hexStr, 0, 16);

					if (!(hex >= 48 && hex <= 57) || //0-9  
								(hex >=97 && hex <= 122) ||   //a-z  
								(hex >=65 && hex <= 90) ||    //A-Z  
								(hex == 0x2d ) || (hex == 0x2e) || (hex == 0x2f) || (hex == 0x5f)) 
								
					{
						outbuf[j++] = char(hex);
						i += 2; 
					}
					else 
						outbuf[j++] = '%';
				}else {
					outbuf[j++] = '%';
					//result += '%';  
				}
				break; 
			default: 
				//result += szToDecode[i];  
				outbuf[j++] = inbuf[i];
				break;  
		} 

	}  
	return j;  
}

void Basetalkspace::date_release()
{
    if (username)
    {
        delete[] username;
        username = NULL;
    }

    if (password)
    {
        delete[] password;
        password = NULL;
    }

    if (content)
    {
        delete[] content;
        content = NULL;
    }

    if (title)
    {
        delete[] title;
        title = NULL;
    }

}


