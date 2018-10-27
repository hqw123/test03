#ifndef  THUNDER_H
#define  THUNDER_H
#include  <boost/unordered_map.hpp>
#include  <boost/function.hpp>

// TODO: this SHOULD be designed as an parser-framework-like interface
// deattached parser and handlers leads more flexible
class p2p
{
	public:
		p2p();
		~p2p();

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
		}request_t;

		typedef struct up_info
		{
			endpoint_t  ep;
			request_t   rqi;
            unsigned int clueid;
            unsigned int captime;
		}up_info_t;

		int push(up_info_t*);

		// add more actions here if any
		enum { act_thunder_login = 0x01 };

	public:
		// for get instance
		static inline
		p2p* instance(void)
		{ return instance_ ? instance_ : instance_ = new p2p(); }

	private:
		inline 
		void handler_call(up_info_t *up)
		{ 
			hdl_map_t::iterator ret;
			ret = p2p_cli_maps_.find(up->rqi.host);
			if (ret != p2p_cli_maps_.end())
				(*ret).second(this, up);
		}
		// for thunder client detection handler
		void parse_thunder_client(up_info_t*);

		void save_result(up_info_t *, int, int);

	private:
		typedef boost::function<void (p2p*, p2p::up_info_t*)> parse_handler_t;
		typedef boost::unordered_map<std::string, parse_handler_t> hdl_map_t;

		hdl_map_t p2p_cli_maps_;

	private:
		static p2p* instance_;
};


#endif  /*THUNDER_H*/
