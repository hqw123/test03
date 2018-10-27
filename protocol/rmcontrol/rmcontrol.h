#ifndef  RMCONTROL_H
#define  RMCONTROL_H

#include  <byteswap.h>
#include  <boost/unordered_map.hpp>
#include  <boost/function.hpp>
#include  <set>
#include  <vector>

struct PacketInfo;
struct tcphdr;

class rmcontrol
{
	public:
		rmcontrol();
		~rmcontrol();
	
		int push(struct PacketInfo* pktinfo);	
	private:
		// NOTE: 
		// <rdp> for 3389 microsoft remote desktop protocol
		// <tv> for teamview protocol
		// parse_continue: we doesn't like this packet, follow down
		// parse_break: we already handled this packet, notify the uplayer to continue the packet loop
		enum { parse_continue = 0, parse_break = 1 };
		enum { pkt_unknwon = -1, pkt_rdp = 1, pkt_tv = 2, pkt_radmin = 3 };

		// pkt_active_mask: check if the packet is ACTIVE for us
		// than means we need this packet and MUST handle it
		enum { pkt_active_mask = 0x0F };

		// NOTE: the radmin server may change the port
		enum { rdp_port = 3389, tv_port = 5938, radmin_port = 4899 };

		// rdp_nr: connection request, nr_cfrm: connection confirm, nr_drop: dropped connections
		// stolen from wireshark
		enum { rdp_nr = 0x01, rdp_nr_cfrm = 0x02, rdp_nr_drop = 0x03 };

		// radmin protocols
		// radmin_hdr_login: used to identify the online action
		// radmin_act_auth: used to identify the user authentication action
		enum { radmin_hdr_login = 0x00000001, radmin_act_auth = 0x0808 };

		// teamview protocols works well on version:12.0.72365
		// tv_hdr_lookup: used to identify the online action
		// tv_hdr_get: used to identify whether the remote desktop procdure is processed(NOT USED NOW)
		// tv_role_controller: used to identify whether we are the controller
		// tv_role_controllee: used to identify whether we are the controllee
		enum { tv_hdr_lookup = 0x1724, tv_hdr_get = 0x1130, 
			 tv_role_controller = 0x000C, tv_role_controllee = 0x0008 };

		// COTP and TPKT protocols, just test on some bits not the whole spec
		// stolen from wireshark
		enum { cotp_pdu_conn_req = 0x0E, cotp_pdu_conn_cfrm = 0x0D };

		// used by all rm action results
		// FIXME: these values MUST be compatible with that in SQL
		// rmc_onl: online action detected
		// rmc_drop: offline action detected
		// rmc_ctrler: controller action detected
		// rmc_ctrlee: controllee action detected
		enum { rmc_unknown = 0x00, rmc_onl = 0x01, rmc_drop = 0x02, rmc_ctrler = 0x03, rmc_ctrlee = 0x04 };
		enum { rmc_active_mask = 0x0F };


	private:
		typedef struct tpkt_hdr
		{
			uint8_t 	ver;
			uint8_t 	reserved;
			uint16_t 	totlen;
		} __attribute__ ((packed)) tpkt_hdr_t;

		typedef struct cotp_hdr
		{
			uint8_t 	totlen;	
			uint8_t 	pdu_type;
			uint16_t 	dref;
			uint16_t 	sref;
			uint8_t 	cls;
		} __attribute__ ((packed)) cotp_hdr_t;

		typedef struct rdp_hdr
		{
			uint8_t 	type;
			uint8_t 	flags;
			uint8_t 	len;
			uint32_t  	proselt;
		} __attribute__ ((packed)) rdp_hdr_t;

		typedef struct rmc_session
		{
			// session L2 info
			// SHOULD we need the damned mac address here ?
			uint8_t srcmac[6];
			uint8_t dstmac[6];

			// session L3 info
			uint32_t sip;
			uint16_t sport;
			uint32_t dip;
			uint16_t dport;
			// FIXME: 
			// this type should be compatible with the values in SQL table
			// it should be an action type, online/offline
			int		 type;
            //protocol type
            int      pro_type;
			// 0: c to s, 1 s to c
			int 	 c2s;
		}rmc_session_t;

	private:
		// check wether the packet is what we need or not...
		int validate(struct tcphdr* tcphdr);

		// handlers
		void handle_teamview_prot(PacketInfo*);
		void handle_msrdp_prot(PacketInfo*);
		void handle_radmin_prot(PacketInfo*);

		inline
		void handler_call(int id, PacketInfo* pktinfo)
		{ prot_hdls_[id](this, pktinfo); }

		// parsers
		int parse_teamview(uint8_t *buffer, size_t len);
		int parse_ms_rdp(uint8_t *buffer, size_t len);
		int parse_radmin(uint8_t *buffer, size_t len);

		// session operations
		rmc_session_t* create_rmc_session(PacketInfo *pktinfo, int act);
		// remote it when we received RST, FIN / RST, ACK
		void remove_rmc_session(struct PacketInfo* pktinfo);
		bool check_if_session_exist(struct PacketInfo* pktinfo) __attribute__ ((deprecated));
		bool check_if_active_session(struct PacketInfo* pktinfo);

		// helper functions
		inline
		size_t tpkt_hdr_len()
		{ return sizeof(tpkt_hdr_t); }

		inline
		size_t cotp_hdr_len()
		{ return sizeof(cotp_hdr_t); }

		inline
		size_t rdp_hdr_len()
		{ return sizeof(rdp_hdr_t); }

		inline
		uint8_t cotp_pdu_translate(uint8_t type)
		{ return ((type & 0x0F) << 4) | ((type & 0xF0) >> 4); }

		// save the result
		void save_rdp_result(rmc_session_t* rs);
		void save_tv_result(rmc_session_t* rs);
		void save_radmin_result(rmc_session_t* rs);
		// actual save function
		void save_action_result(rmc_session_t* rs);

		uint64_t make_hashkey(PacketInfo *pktinfo, bool reverse = true);

		// make hash value
		// source ip address are the same(only in our project) so don't use it
		inline
		uint64_t make_hashkey(rmc_session_t *rs)
		{ return ((uint64_t)(rs->dip & 0xFFFFFFFF) << 32) | (uint64_t)((uint32_t)rs->sport << 16 | (uint32_t)rs->dport); }

		typedef boost::function<void (rmcontrol*, PacketInfo*)> prot_handler_t;
	private:
		// we only save ms_rdp sessions in the table now
		// used by <check_if_session_exist>, <check_if_active_session>
		boost::unordered_map<uint64_t, rmc_session_t*> rdp_sess;
		// handle table for lookup in constant time
		std::vector<prot_handler_t> prot_hdls_;
};


#endif  /*RMCONTROL_H*/
