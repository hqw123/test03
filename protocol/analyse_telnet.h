#ifndef TELNET_H
#define TELNET_H

#include <map>
#include <string>
#include "PacketParser.h"
using namespace std;

typedef struct packet_element_telnet
{
	string username;
	string password;
	int flag; //  1表示用户名 2表示密码
}Pack_Elem_telnet;

class Telnet
{
private:
	
	map<unsigned long,Pack_Elem_telnet> user_message;
	
	bool s_to_c;
	unsigned long c_index;
	unsigned long s_index;
	PacketInfo* packet_info;
	char* body;
	int bodylen;

	void init();
	void store_database();
	
	bool analyse_server();
	bool analyse_client();
	
public:
	
	Telnet();
	~Telnet();
	
	bool analyse_telnet(PacketInfo* pktInfo);
};


#endif 

