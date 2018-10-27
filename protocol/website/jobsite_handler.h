#ifndef  JOBSITE_HANDLER_H
#define  JOBSITE_HANDLER_H
#include  <sys/types.h>
#include  "../http_get.h"

struct tuple;

struct jobsite_info
{
	struct tuple tp;
	char   *src_mac;
	char   *d_buf;
	size_t d_len;
	//char   d_charset[16];
};

enum
{
    JOB_51 = 1901,
    JOB_ZL,
};

class jobsite_handler
{
	public:
		jobsite_handler();
		~jobsite_handler();
        int deal_packet_process(unsigned short type, PacketInfo* packet, bool is_from_server);
	private:
		enum
		{
			MAX_NAME_LEN = 11*2 + 2,
			MAX_PHONE_LEN = 12,
			MAX_ADDR_LEN = 100*2 + 2
		};
	private:
	
        // FIXME: these interface is a poor design
    
		void parase_51_info(const jobsite_info *node, unsigned short type);
		void parase_zl_info(const jobsite_info *node, unsigned short type);
		void parase_lp_info(const jobsite_info *node);

		bool copy_value_among_ab(const char *data, size_t inlen, char *obuf, size_t *olen);
        int rebuilt_packet(char* data, unsigned int dataLen);
        int decomp_gzip(char *src, unsigned int len, char **dest);
        int analyse_job(unsigned short type, PacketInfo* packet);
        void realease_pack();
        bool get_51job_addr(const char *data, size_t inlen, char *obuf, size_t olen);
	private:
		
        unsigned short m_job_type;
        struct pack_node
        {
            char* header;
            unsigned int headerLen;
            char *body;
            unsigned int bodyLen;
            unsigned int bodyTotal;
            unsigned int status;
        }m_entry;
};

#endif  /*JOBSITE_HANDLER_H*/
