#ifndef  BLOG_H
#define  BLOG_H

#include  <string>
#include  <vector>
#include  <exception>

#include  <boost/unordered_map.hpp>
#include  <boost/bind.hpp>
#include  <boost/function.hpp>
#include  <boost/algorithm/string.hpp>

class blog
{
	public:
		enum 
		{ 
			blog_unknown = -1,
			blog_sina = 0,
			blog_sohu = 1,
			blog_163 = 2,
			blog_qq = 3,
			blog_ifeng = 4
		};

		enum 
		{
			blog_act_post,
			blog_act_comment
		};

		enum 
		{
			max_subject_len = 512,
			max_content_len = 1024*1024*2
		};
		typedef struct endpoint
		{
			uint8_t  srcmac[6];
			uint8_t  dstmac[6];
			uint32_t srcip;
			uint16_t srcport;
			uint32_t dstip;
			uint16_t dstport;
		}endpoint_t;
	
		typedef struct request
		{
			std::string host;
			std::string uri;
			std::string cookie;
			char *d;
			size_t dlen;
		}request_t;

		typedef struct up_info
		{
			endpoint_t  ep;
			request_t   rqi;
            unsigned int clueid;
            unsigned int captime;
		}up_info_t;

		blog();
		~blog();

		static blog *instance();

	public:
		int push(up_info_t *upt);

	private:
		// PC
		void parse_163_blog(request_t *req);
		void parse_sina_blog(request_t *req);
		void parse_sohu_blog(request_t *req);
		void parse_tianya_blog(request_t *req);
		void parse_ifeng_blog(request_t *req);
	
		// Mobile
		void parse_mbsina_blog(request_t *req);

		// PC
		int  analyse_163_action(const std::string& uri);
		int  analyse_sina_action(const std::string& uri);
		int  analyse_sohu_action(const std::string& uri);
		int  analyse_tianya_action(const std::string& uri);
		int  analyse_ifeng_action(const std::string& uri);

		// Mobile
		int analyse_mbsina_action(const std::string& uri);

		// PC
		bool parse_account_info(const std::string& pattern, const std::string& cookie, std::string& out);
		void parse_163_account(request_t *req, std::string& out);	
		void parse_sina_account(request_t *req, std::string& out);	
		void parse_sohu_account(request_t *req, std::string& out);	
		void parse_tianya_account(request_t *req, std::string& out);	
		void parse_ifeng_account(request_t *req, std::string& out);	

		void parse_163_content(const std::string& stmin, std::string& new_content);
		void parse_sina_content(const std::string& stmin, std::string& new_content);
		void parse_sohu_content(const std::string& stmin, std::string& new_content);
		void parse_tianya_content(const std::string& stmin, std::string& new_content);
		void parse_ifeng_content(const std::string& stmin, std::string& new_content);
		void parse_blog_content(const std::string& stmin, const std::string& content_key, std::string& content);
		void parse_mbsina_content(const std::string& stmin, std::string& new_content);

		// Mobile
		void parse_mbsina_account(request_t *req, std::string& out);

		enum { Key_Int = 0, Key_String = 1, Key_Float = 2, Key_Bolean = 3, Key_Object = 4 };

		// FIXME:use struct here, use the pair here is a bad design
		// we also can use the boost::any
		// typedef struct value_pair
		// {
		// 	int  type;
		// 	std::string value;
		// }result_163value_type;
		typedef std::pair<int, std::string>  result_163value_type;
		typedef std::string result_key_type;
		typedef std::string result_value_type;

		typedef std::vector<std::string> split_result_type;

		template <typename AssociateT>
		void parse_163_comment(const std::string& cmt, AssociateT& results);
	
		template <typename AssociateT>
		void read_lines(const std::string& read_from, AssociateT& outc);

		// this maybe a genera code
		// data format: key=value&key=value&.....
		template <typename AssociateT>
		void parse_sina_comment(const std::string& cmt, AssociateT& results);
		
		template <typename AssociateT>
		void parse_tianya_comment(const std::string& cmt, AssociateT& results);

		// these two is not implemented yet
		template <typename AssociateT>
		void parse_sohu_comment(const std::string& key, AssociateT& results);

		template <typename AssociateT>
		void parse_ifeng_comment(const std::string& key, AssociateT& results);
		// ...
	
		// we need this function to parse the text like the follows:
		// "method=blog.ice.savenewComment&params.f=0&params.blogId=7495855&...
		// whitch is of "key1=value1&key2=value2...." format
		template <typename AssociateT>
		void parse_internet_string(const std::string& buffer, AssociateT& results);

		template <typename AssociateT>
		void parse_163_comment_object(const std::string& obj, AssociateT& results);

		void save(const std::string& data_stream, const std::string &dir, const std::string& cls);
		void save_content(const std::string& content, const std::string& dir); 
		void save_comment(const std::string& comment, const std::string& dir);

		bool parse_subject(const std::string& pattern, const std::string& content, std::string& subject);

		// helper functions
		// int url_decode(const char *inbuf, size_t inlen, char *outbuf, size_t olen);
		int url_decode(const std::string& instr, std::string& outstr);
        void storedb(int type);

		typedef boost::function<void (blog*, blog::request_t *)> parse_handler_t;

	private:
		static blog *instance_;

	private:
		std::string path_to_save_;
		boost::unordered_map<std::string, parse_handler_t> vblog_types_;

        std::string username;
        std::string userid;
        std::string articleid;
        std::string subject;
        std::string content_path;

        up_info_t *base_info;
};

#include  "blog.inl"

#endif  /*BLOG_H*/
