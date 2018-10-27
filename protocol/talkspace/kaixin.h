#ifndef KAIXIN_H_
#define KAIXIN_H_	

#include "basetalkspace.h"

class Kaixin : public Basetalkspace
{
private:
	char userid[20];
	char passive_userid[20];
	char post_id[20];

	std::string store_path;
	pcre* match_passive_userid;

	/*deal PC client data*/
	int get_content();
	int get_title();
	int get_login();
	int get_username();
	int get_userid();
	int get_record();
	int get_diary();
	int get_comment();
	int get_passive_userid();
	int get_postid();
	int get_chat();
	int get_instation_postmessage();
	int get_instation_replymessage();
	
	/*deal phone client data*/
	int client_get_login();
	int client_get_password();
	int client_get_username();
	int client_get_content();
	int client_get_userid();
	int client_get_record();
	
	void storedb();
	void storemsgdb();
    void store_user_pass();
	int store_file(char* type);

public:
	Kaixin();
	~Kaixin();
	
	int analyse_kaixin(common_tcp* tcp,common_http* http,int id);
};

#endif 


