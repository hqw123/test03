
#include  <sys/time.h>
#include  <iostream>
#include  <boost/filesystem.hpp>
//#include  <boost/locale.hpp>
#include  <sstream>
#include  <fstream>
#include  <arpa/inet.h>
#include  <iconv.h>

#include  "blog.h"
#include  "db_data.h"


blog *blog::instance_;

blog::blog()
{
	// NOTE: add more blogs here if available
	vblog_types_.insert(std::make_pair("api.blog.163.com", parse_handler_t(&blog::parse_163_blog)));
	vblog_types_.insert(std::make_pair("blog.tianya.cn", parse_handler_t(&blog::parse_tianya_blog)));
	vblog_types_.insert(std::make_pair("control.blog.sina.com.cn", parse_handler_t(&blog::parse_sina_blog)));
	vblog_types_.insert(std::make_pair("blog.ifeng.com", parse_handler_t(&blog::parse_ifeng_blog)));
	vblog_types_.insert(std::make_pair("blog.sohu.com", parse_handler_t(&blog::parse_sohu_blog)));

	// mobile blog clients
	vblog_types_.insert(std::make_pair("app.blog.sina.com.cn", parse_handler_t(&blog::parse_mbsina_blog)));

	// change it if necessary 
	path_to_save_ = "/home/spyData/moduleData/blog/";
	
	if (!boost::filesystem::exists(path_to_save_))
		boost::filesystem::create_directories(path_to_save_);
}

blog::~blog()
{

}

blog *blog::instance()
{
	if (!instance_)
		return instance_ = new blog();
	else
		return instance_;
}

// we don't need this function cause the content is a plain text, just write it to file
//int blog::url_decode(const char *inbuf, size_t inlen, char *outbuf, size_t olen)
int blog::url_decode(const std::string& instr, std::string& outbuf)
{  
	//std::string result; 
	char *inbuf = const_cast<char *>(instr.c_str());
	size_t inlen = instr.length();
	outbuf.resize(inlen * 4);
	//char *outbuf = outstr.c_str();
	size_t olen = outbuf.size();

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
								(hex == 0x2d ) || (hex == 0x2e) || (hex == 0x2f) || (hex == 0x5f)) //[-/_/./~] 
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

void blog::storedb(int type)
{
	struct in_addr addr;
	BLOG_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	tmp_data.p_data.clueid = base_info->clueid;
	tmp_data.p_data.readed = 0;

	addr.s_addr = base_info->ep.srcip;
	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x", base_info->ep.srcmac[0]&0xff, base_info->ep.srcmac[1]&0xff, 
            base_info->ep.srcmac[2]&0xff, base_info->ep.srcmac[3]&0xff, base_info->ep.srcmac[4]&0xff, base_info->ep.srcmac[5]&0xff);
	sprintf(tmp_data.p_data.clientPort, "%d", base_info->ep.srcport);
	addr.s_addr = base_info->ep.dstip;
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));
	sprintf(tmp_data.p_data.serverPort, "%d", base_info->ep.dstport);
	
	strncpy(tmp_data.username, username.c_str(), 49);
	strncpy(tmp_data.userid, userid.c_str(), 19);
    strncpy(tmp_data.articleid, articleid.c_str(), 19);
    strncpy(tmp_data.title, subject.c_str(), 199);
	strncpy(tmp_data.content_path, content_path.c_str(), 255);

    tmp_data.p_data.captureTime = base_info->captime;
    tmp_data.p_data.proType = type;
    tmp_data.p_data.deleted = 0;
    
	msg_queue_send_data(BLOG, (void *)&tmp_data, sizeof(tmp_data));
}

int  blog::analyse_163_action(const std::string& uri)
{
	if (std::string::npos != uri.find("editBlogNew"))
		return blog_act_post;
	else if (std::string::npos != uri.rfind("addBlogComment"))
		return blog_act_comment;
	else
		return -1;
}

int  blog::analyse_sina_action(const std::string& uri)
{
	if (std::string::npos != uri.rfind("article_post"))
		return blog_act_post;
	else if (std::string::npos != uri.find("comment_new"))
		return blog_act_comment;
	
	return -1;
}

// we can't visit the blog.sohu.com till now
int  blog::analyse_sohu_action(const std::string& uri)
{
	if (std::string::npos != uri.find("/manage/entry"))
		return blog_act_post;
	
	return -1;
}

int  blog::analyse_tianya_action(const std::string& uri)
{
	if (std::string::npos != uri.find("insertBlogArticle"))
		return blog_act_post;
	else if (std::string::npos != uri.find("/api/blog"))
		return blog_act_comment;

	return -1;
}

int  blog::analyse_ifeng_action(const std::string& uri)
{
	if (std::string::npos != uri.find("/usercp"))
		return blog_act_post;

	return -1;
}

bool blog::parse_account_info(const std::string& pattern, const std::string& cookie, std::string& out)
{
	std::string::size_type spos = cookie.find(pattern);
	if (std::string::npos != spos)
	{
		spos += pattern.length();
		std::string::size_type epos = cookie.find(';', spos);
		if (std::string::npos != epos)
		{
			out = cookie.substr(spos, epos - spos);
			return true;	
		}
	}

	return false;
}

void blog::parse_163_account(request_t *req, std::string& out)
{
	std::string acc_patn("P_INFO=");
	split_result_type  result;
	this->parse_account_info(acc_patn, req->cookie, out);
	boost::split(result, out, boost::is_any_of("|"));
	if (!result.empty())
		out = result[0];
}

void blog::parse_sina_account(request_t *req, std::string& out)
{
	return;
}

void blog::parse_sohu_account(request_t *req, std::string& out)
{
	return;
}

void blog::parse_tianya_account(request_t *req, std::string& out)
{
	std::string acc_patn("user=");
	split_result_type res;
	std::string temp;

	this->parse_account_info(acc_patn, req->cookie, out);
	boost::split(res, out, boost::is_any_of("&"));
	if (!res.empty())
	{
		temp = res[0];
		res.clear();
		boost::split(res, temp, boost::is_any_of("="));
		if (!res.empty())
			out = res[1];
	}
}

void blog::parse_ifeng_account(request_t *req, std::string& out)
{
	std::string acc_patn("IF_USER=");
	std::string temp;
		
	this->parse_account_info(acc_patn, req->cookie, temp);
	this->url_decode(temp, out);
}

bool blog::parse_subject(const std::string& pattern, const std::string& content, std::string& subject)
{
	std::string::size_type spos, epos;
	spos = content.find(pattern);
	if (std::string::npos != spos)
	{
		spos += pattern.length();
		epos = content.find('&', spos);
		if (std::string::npos != epos)
		{
			std::string rawsub;
			rawsub = content.substr(spos, epos - spos);
			this->url_decode(rawsub, subject);
			return true;
		}
	}

	return false;
}

int blog::push(up_info_t *upt)
{
	boost::unordered_map<std::string, parse_handler_t>::iterator it;
	it = vblog_types_.find(upt->rqi.host);
	if (it != vblog_types_.end())
	{
	    base_info = upt;
		parse_handler_t handler = (*it).second;
		handler(this, &upt->rqi);
	}
	else
	{
		//std::cout << __FILE__ << ":" << __LINE__ << " unsupported blog type" << std::endl;
		return -1;
	}

	return 0;
}


void blog::save(const std::string& data_stream, const std::string &dir, const std::string& cls)
{
	struct timeval  tv;
	std::stringstream  ss;
	std::string file_to_save = path_to_save_ + dir;
	std::ofstream file_h;

	if (file_to_save[file_to_save.length() - 1] != '/')
		file_to_save += '/';

	gettimeofday(&tv, NULL);

	if (!boost::filesystem::exists(file_to_save))
		boost::filesystem::create_directories(file_to_save);
	ss << file_to_save << cls << "-" << tv.tv_sec << '-' << tv.tv_usec;
	content_path = ss.str();
	file_h.open(content_path.c_str(), std::ios_base::out | std::ios_base::binary);
	file_h << data_stream << std::endl;
	file_h.close();

}

void blog::save_content(const std::string& content, const std::string& dir)
{
	this->save(content, dir, "content");
	//std::cout << "content: \n" << content << std::endl;
}

void blog::save_comment(const std::string& comment, const std::string& dir)
{
	std::string cmdec;
	this->url_decode(comment, cmdec);
	this->save(cmdec, dir, "comment");
	//std::cout << "comment:\n" << cmdec << std::endl;
}

int blog::analyse_mbsina_action(const std::string& uri)
{
	if (std::string::npos != uri.find("article_add"))
		return blog_act_post;
	else if (std::string::npos != uri.find("comment_add"))
		return blog_act_comment;

	return -1;
}

void blog::parse_mbsina_account(request_t *req, std::string& out)
{
	std::string content(req->d);
	std::string::size_type spos = content.find("login_uid=");
	
	if (spos != std::string::npos)
	{
		spos += std::string("login_uid=").length();
		std::string::size_type epos = content.find('&', spos);
		out = content.substr(spos, epos - spos);
	}
}

void blog::parse_mbsina_blog(request_t *req)
{
	std::string content(req->d), subject_patn("article_title=");

	int action = this->analyse_mbsina_action(req->uri);

	switch (action)
	{
		case blog_act_post:
			{
				this->parse_mbsina_account(req, username);
				this->parse_subject(subject_patn, content, subject);

				std::string new_content;
				this->parse_mbsina_content(content, new_content);
				this->save_content(new_content, "sina/");
                userid = "";
                articleid = "";
				break;
			}
		case blog_act_comment:
			{
				typedef boost::unordered_map<result_key_type, result_value_type> result_type;
				typedef result_type::iterator iterator;

				result_type  results;
				std::string key_article_id("article_id"), key_loginuid("login_uid");
				std::string key_comment("comment_content");

				this->parse_sina_comment(content, results);
				if (!results.empty())
				{
					iterator it;
					it = results.find(key_article_id);
					articleid = (it == results.end()) ? "" : (*it).second; 

					it = results.find(key_loginuid);
					userid = (it == results.end()) ? "" : (*it).second;
				}
				
				iterator cmit = results.find(key_comment);
				if (cmit != results.end())
					this->save_comment((*cmit).second, "sina/");
                username = "";
                subject = "";
				break;
			}
		default:
			break;
	}

    storedb(1301);
}

void blog::parse_blog_content(const std::string& stmin, const std::string& content_key, std::string& content)
{
	typedef boost::unordered_map<result_key_type, result_value_type> result_type;
	typedef std::vector<std::string> split_result_type;
	split_result_type results1;
	result_type results3;

	split_result_type::iterator it;

	boost::split(results1, stmin, boost::is_any_of("&"));
	it = results1.begin();
	for (; it != results1.end(); ++it)
	{
		split_result_type results2;
		boost::split(results2, (*it), boost::is_any_of("="));
		results3[results2[0]] = results2[1];
	}

	result_type::iterator findit = results3.find(content_key);
	if (findit != results3.end())
		content = (*findit).second;
}

void blog::parse_ifeng_content(const std::string& stmin, std::string& new_content)
{
	std::string content_unpacked;
	std::string key = "message";
	this->parse_blog_content(stmin, key, content_unpacked);
	this->url_decode(content_unpacked, new_content);
}

void blog::parse_mbsina_content(const std::string& stmin, std::string& new_content)
{
	std::string content_unpacked;
	std::string key = "article_body";
	this->parse_blog_content(stmin, key, content_unpacked);
	this->url_decode(content_unpacked, new_content);
}

void blog::parse_tianya_content(const std::string& stmin, std::string& new_content)
{
	std::string content_unpacked;
	std::string key = "params.content";
	this->parse_blog_content(stmin, key, content_unpacked);
	this->url_decode(content_unpacked, new_content);
}

void blog::parse_sohu_content(const std::string& stmin, std::string& new_content)
{
	std::string content_unpacked;
	std::string key = "entrycontent";
	std::string utf8_content;

	this->parse_blog_content(stmin, key, content_unpacked);
	this->url_decode(content_unpacked, new_content);
	
	utf8_content.resize(new_content.size()*4);
	iconv_t cp = iconv_open("utf-8", "gbk");
	if (cp == (iconv_t)-1)
		return;

	size_t insize = new_content.size();
	size_t outsize = utf8_content.capacity();
	char *inbuf = const_cast<char *>(new_content.c_str());
	char *outbuf = const_cast<char *>(utf8_content.c_str());
	
	if (iconv(cp, &inbuf, &insize, &outbuf, &outsize) == (size_t)-1)
		return;

	new_content = utf8_content;
	//std::cout << utf8_content << std::endl;
	// add conversation between "GBK" and "UTF-8"
	//std::string utf8_content = boost::locale::conv::between(new_content, std::string("UTF-8"), std::string("GBK"));
	//new_content = utf8_content;
}

void blog::parse_sina_content(const std::string& stmin, std::string& new_content)
{
	std::string content_unpacked;
	std::string key = "blog_body";
	this->parse_blog_content(stmin, key, content_unpacked);
	this->url_decode(content_unpacked, new_content);
}

void blog::parse_163_content(const std::string& stmin, std::string& new_content)
{
	std::string content_unpacked;
	std::string key = "HEContent";
	this->parse_blog_content(stmin, key, content_unpacked);
	this->url_decode(content_unpacked, new_content);
}

void blog::parse_163_blog(request_t *req)
{
	std::string partial_uri = req->uri.substr(6);
	std::string::size_type pos = partial_uri.find('/');
	std::string content(req->d), subject_patn("&title=");

	// we get the blog nick name from the uri
	std::string blog_nick;

	partial_uri = partial_uri.substr(pos + 1);
	blog_nick = partial_uri.substr(0, pos);

	int action = this->analyse_163_action(partial_uri);

	switch (action)
	{
		case blog_act_post:
			{
				this->parse_163_account(req, username);
				this->parse_subject(subject_patn, content, subject);

				std::string new_content;
				this->parse_163_content(content, new_content);
				this->save_content(new_content, "163/");
                userid = "";
                articleid = "";
				break;
			}
		case blog_act_comment:
			{
				typedef boost::unordered_map<result_key_type, result_163value_type> pred_result_type;
				typedef boost::unordered_map<result_key_type, result_value_type> result_type;
				typedef result_type::iterator  iterator;

				pred_result_type 	pred_result;
				result_type 		obj_results;
				std::string key_blogid("blogId"), key_blog_title("blogTitle"), key_replyto("replyToUserName");
				std::string key_comment("content");
				std::string objstr;

				this->parse_163_comment(content, pred_result);

				// we search the "Object_Object" directly for saving some time
				// FIXME: bug: the keyword "Object_Object" may repeated more than once...
				std::string::size_type s = content.find("Object_Object:");
				if (s != std::string::npos)
					s += std::string("Object_Object:").length();
				else	// we can't do next step without the <Object_Object> field
					break;

				objstr = content.substr(s, content.length() - s);

				this->parse_163_comment_object(objstr, obj_results);
				if (!pred_result.empty() && !obj_results.empty())
				{
					iterator it;
					it = obj_results.find(key_blogid);
					articleid = (it == obj_results.end()) ? "" : pred_result[(*it).second].second;

					it = obj_results.find(key_blog_title);
					subject = (it == obj_results.end()) ? "" : pred_result[(*it).second].second;

					it = obj_results.find(key_replyto);
					username = (it == obj_results.end()) ? "" : pred_result[(*it).second].second;
				}

				iterator cmit = obj_results.find(key_comment);
				if (cmit != obj_results.end())
					this->save_comment(pred_result[(*cmit).second].second, "163/");
                userid = "";
			}
			break;
		default:
			break;
	}

	if (action != -1)
		storedb(1302);
}

void blog::parse_sina_blog(request_t *req)
{
	std::string content(req->d), subject_patn("blog_title=");

	int action = this->analyse_sina_action(req->uri);
	switch (action)
	{
		case blog_act_post:
			{
				this->parse_sina_account(req, username);
				this->parse_subject(subject_patn, content, subject);

				std::string new_content;
				this->parse_sina_content(content, new_content);
				this->save_content(new_content, "sina/");
                userid = "";
                articleid = "";
				break;
			}
		case blog_act_comment:
			{
				typedef boost::unordered_map<result_key_type, result_value_type> result_type;
				typedef result_type::iterator iterator;

				result_type  results;
				std::string key_article_id("article_id"), key_loginname("login_name");
				std::string key_comment("comment");

				this->parse_sina_comment(content, results);

				if (!results.empty())
				{
					iterator it;
					it = results.find(key_article_id);
					articleid = (it == results.end()) ? "" : (*it).second; 

					std::string tmpname;
					it = results.find(key_loginname);
					tmpname = (it == results.end()) ? "" : (*it).second;
					this->url_decode(tmpname, username);	
				}
				
				iterator cmit = results.find(key_comment);
				if (cmit != results.end())
					this->save_comment((*cmit).second, "sina/");

                userid = "";
                subject = "";
			}
			break;
		default:
			break;
	}

	if (action != -1)
		storedb(1301);
}

void blog::parse_sohu_blog(request_t *req)
{
	std::string content(req->d), subject_patn("entrytitle=");

	int action = this->analyse_sohu_action(req->uri);
	switch (action)
	{
		case blog_act_post:
			{
				this->parse_sohu_account(req, username);
				this->parse_subject(subject_patn, content, subject);

				std::string new_content;
				this->parse_sohu_content(content, new_content);
				this->save_content(new_content, "sohu/");
                userid = "";
                articleid = "";
				break;
			}
		case blog_act_comment:
			this->save_content(content, "sohu/");
            username = "";
            userid = "";
            articleid = "";
            subject = "";
			break;
		default:
			break;
	}

	if (action != -1)
		storedb(1304);
}

void blog::parse_tianya_blog(request_t *req)
{
	std::string content(req->d), subject_patn("params.title=");

	int action = this->analyse_tianya_action(req->uri);
	switch (action)
	{
		case blog_act_post:
			{
				this->parse_tianya_account(req, username);
				this->parse_subject(subject_patn, content, subject);

				std::string new_content;
				this->parse_tianya_content(content, new_content);
				this->save_content(new_content, "tianya/");
                userid = "";
                articleid = "";
				break;
			}
		case blog_act_comment:
			{
				typedef boost::unordered_map<result_key_type, result_value_type> result_type;
				typedef result_type::iterator  iterator;
				std::string key_blogid("params.blogId"), key_userid("params.puserId");
				std::string key_comment("params.content");
				result_type results;

				this->parse_tianya_comment(content, results);
				if (!results.empty())
				{
					iterator it;
					it = results.find(key_userid);
					userid = (it == results.end()) ? "" : (*it).second; 

					it = results.find(key_blogid);
					articleid= (it == results.end()) ? "" : (*it).second;
				}

				iterator cmit = results.find(key_comment);
				if (cmit != results.end())
					this->save_comment((*cmit).second, "tianya/");

                username = "";
                subject = "";
				break;
			}
		default:
			break;
	}

	if (action != -1)
		storedb(1303);
}

// we can't visit the website till now
// Fri Mar 10 03:15:26 PST 2017
void blog::parse_ifeng_blog(request_t *req)
{
	std::string subject_patn("subject=");
	std::string content(req->d);

	int action = this->analyse_ifeng_action(req->uri);
	switch (action)
	{
		case blog_act_post:
			{
				this->parse_ifeng_account(req, username);
				this->parse_subject(subject_patn, content, subject);

				std::string new_content;
				this->parse_ifeng_content(content, new_content);
				this->save_content(new_content, "ifeng/");
                userid = "";
                articleid = "";
				break;
			}
		case blog_act_comment:
			this->save_content(content, "ifeng/");
            username = "";
            userid = "";
            articleid = "";
            subject = "";
			break;
		default:
			break;
	}

	if (action != -1)
		storedb(1305);
}
