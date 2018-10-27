#ifndef BASETALKSPACE_H
#define BASETALKSPACE_H

#include <stdlib.h>
#include <stdio.h>
#include <cstring>
#include <string>
#include <pcre.h>
//#include <iostream>

#include "common.h"

class Basetalkspace
{
protected:
	common_tcp* m_tcp;
	common_http* m_http;
	int objectid;
	char* username;
    char* password;
	char* content;
	char* title;

	std::string base_path;
	
	pcre* matchtitle;
	pcre* matchcontent;
	const char* chpError;
	int iErro;

	int url_decode(const char *inbuf, size_t inlen, char *outbuf, size_t olen);
	void date_release();
		
public:
	Basetalkspace();
	virtual ~Basetalkspace();
};

#endif


