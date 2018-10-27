
#include  <arpa/inet.h>

#include  "rmcontrol.h"
#include  "../PacketParser.h"
#include  "db_data.h"
#include  "clue_c.h"

rmcontrol::rmcontrol()
{
	prot_hdls_.resize(16);
	// add more handlers here if any
	// pkt_rdp
	prot_hdls_[pkt_rdp] = &rmcontrol::handle_msrdp_prot;
	// pkt_tv
	prot_hdls_[pkt_tv] = &rmcontrol::handle_teamview_prot;
	// pkt_radmin
	prot_hdls_[pkt_radmin] = &rmcontrol::handle_radmin_prot;
}

rmcontrol::~rmcontrol()
{

}

void rmcontrol::handle_teamview_prot(PacketInfo* pktinfo)
{
	int act_type = this->parse_teamview(reinterpret_cast<uint8_t *>(pktinfo->body), pktinfo->bodyLen);
	if (act_type & rmc_active_mask)
	{
		rmc_session_t *rs = this->create_rmc_session(pktinfo, act_type);
		this->save_tv_result(rs);
	}
}

void rmcontrol::handle_msrdp_prot(PacketInfo* pktinfo)
{
	int act_type = this->parse_ms_rdp(reinterpret_cast<uint8_t *>(pktinfo->body), pktinfo->bodyLen);
	if (act_type & rmc_active_mask)
	{
		rmc_session_t *rs = this->create_rmc_session(pktinfo, act_type);
		this->save_rdp_result(rs);
	}
}

void rmcontrol::handle_radmin_prot(PacketInfo* pktinfo)
{
	int act_type = this->parse_radmin(reinterpret_cast<uint8_t *>(pktinfo->body), pktinfo->bodyLen);
	if (act_type & rmc_active_mask)
	{
		rmc_session_t *rs = this->create_rmc_session(pktinfo, act_type);
		this->save_radmin_result(rs);
	}
	
}

int rmcontrol::validate(struct tcphdr* tcphdr)
{
	uint16_t dport = bswap_16(tcphdr->dest);
	uint16_t sport = bswap_16(tcphdr->source);

	if (dport == rdp_port || sport == rdp_port)
		return pkt_rdp;
	else if (dport == tv_port || sport == tv_port)
		return pkt_tv;
	else if (dport == radmin_port || sport == radmin_port)
		return pkt_radmin;
	
	return pkt_unknwon;
}

rmcontrol::rmc_session_t* rmcontrol::create_rmc_session(PacketInfo *pktinfo, int act)
{
	rmc_session_t *rs = new rmc_session_t;
	rs->sip = pktinfo->ip->saddr;
	rs->dip = pktinfo->ip->daddr;
	rs->sport = pktinfo->tcp->source;
	rs->dport = pktinfo->tcp->dest;
	rs->type = act;
	memcpy(rs->srcmac, pktinfo->srcMac, sizeof(rs->srcmac));
	memcpy(rs->dstmac, pktinfo->destMac, sizeof(rs->dstmac));

	rdp_sess.insert(std::make_pair(this->make_hashkey(rs), rs));

	return rs;
}

uint64_t rmcontrol::make_hashkey(PacketInfo *pktinfo, bool reverse)
{
	uint32_t sip = bswap_32(pktinfo->ip->daddr);
	uint32_t dip = bswap_32(pktinfo->ip->saddr);
	uint16_t sport = bswap_16(pktinfo->tcp->source);
	uint16_t dport = bswap_16(pktinfo->tcp->dest);

	return  reverse ? (((uint64_t)(sip & 0xFFFFFFFF) << 32) | (uint64_t)((uint32_t)dport << 16 | (uint32_t)sport)) : \
		(((uint64_t)(dip & 0xFFFFFFFF) << 32) | (uint64_t)((uint32_t)sport << 16 | (uint32_t)dport));
}

bool rmcontrol::check_if_active_session(struct PacketInfo* pktinfo)
{
	struct tcphdr* tcp = pktinfo->tcp;
	
	// if we found a RST or FIN on the exist session
	// we remove it from the table and record it to SQL
	// this->remove_rmc_session(pktinfo);
	boost::unordered_map<uint64_t, rmc_session_t*>::iterator ret, ret1, ret2;
	ret1 = rdp_sess.find(this->make_hashkey(pktinfo));
	ret2 = rdp_sess.find(this->make_hashkey(pktinfo, false));
	
	ret = ret1 != rdp_sess.end() ? ret1 : (ret2 != rdp_sess.end() ? ret2 : rdp_sess.end());

	if (ret2 != rdp_sess.end())
		(*ret2).second->c2s = 1;
	// test if we found a RST or FIN on the exist RMC session
	// but we SHOULD not write this boring code here...
	// so ugly code here...
	if (ret != rdp_sess.end())
	{
		if (tcp->fin || tcp->rst)
		{
			rmc_session_t* rs = (*ret).second;
			rs->type = rmc_drop;
			this->save_rdp_result((*ret).second);
			rdp_sess.erase(ret);
			delete (*ret).second;
			return true;
		}
	}

	return false;
}

void rmcontrol::save_action_result(rmc_session_t* rs)
{
	/*write remote control data to shared memory, by zhangzm*/
    struct in_addr addr;
	APP_BEHAVIOR_T tmp_data;
	memset(&tmp_data, 0, sizeof(tmp_data));
	
	if (!rs->c2s)
		addr.s_addr = rs->sip;
	else 
		addr.s_addr = rs->dip;

	strcpy(tmp_data.p_data.clientIp, inet_ntoa(addr));

	if (!rs->c2s)
		sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x", rs->srcmac[0]&0xff,
				rs->srcmac[1]&0xff, rs->srcmac[2]&0xff, rs->srcmac[3]&0xff, rs->srcmac[4]&0xff, rs->srcmac[5]&0xff);
	else
		sprintf(tmp_data.p_data.clientMac, "%02x-%02x-%02x-%02x-%02x-%02x", rs->dstmac[0]&0xff,
				rs->dstmac[1]&0xff, rs->dstmac[2]&0xff, rs->dstmac[3]&0xff, rs->dstmac[4]&0xff, rs->dstmac[5]&0xff);
    
	if (!rs->c2s)
		sprintf(tmp_data.p_data.clientPort, "%d", ntohs(rs->sport));
	else
		sprintf(tmp_data.p_data.clientPort, "%d", ntohs(rs->dport));

	if (rs->c2s)
		addr.s_addr = rs->sip;
	else
		addr.s_addr = rs->dip;
		
	strcpy(tmp_data.p_data.serverIp, inet_ntoa(addr));

	if (rs->c2s)
	    sprintf(tmp_data.p_data.serverPort, "%d", ntohs(rs->sport));
    else
        sprintf(tmp_data.p_data.serverPort, "%d", ntohs(rs->dport));

	tmp_data.p_data.clueid = get_clue_id(tmp_data.p_data.clientMac, tmp_data.p_data.clientIp);
	tmp_data.p_data.readed = 0;

	tmp_data.p_data.captureTime = (unsigned int)time(NULL);
    tmp_data.optype = rs->type;
	tmp_data.p_data.proType = rs->pro_type;
	tmp_data.p_data.deleted = 0;
    
	msg_queue_send_data(REMOTE_CONTROL, (void *)&tmp_data, sizeof(tmp_data));
}

int rmcontrol::push(struct PacketInfo* pktinfo)
{
	struct tcphdr* tcp = pktinfo->tcp;
	int act_type;

	int prot_type = this->validate(tcp);
	if (prot_type == pkt_unknwon)
		return parse_continue;

	// we check if the continous data comes in, we don't like it
	if (this->check_if_active_session(pktinfo))
		return parse_break;
	
	this->handler_call(prot_type, pktinfo);

	// we always return parse_break when we detected the remote protocols so that the packet will not be followed down
	return prot_type & pkt_active_mask ? parse_break : parse_continue;
	//return act_type == 0 ? parse_continue : parse_break;
}

int rmcontrol::parse_teamview(uint8_t *buffer, size_t len)
{
	uint16_t hdr_bits = bswap_16(*(uint16_t *)buffer);
	uint16_t act_bits = bswap_16(*(uint16_t *)(buffer + sizeof(hdr_bits)));
	uint16_t role_bits = bswap_16(*(uint16_t *)(buffer + sizeof(hdr_bits) + sizeof(role_bits)));

	if (hdr_bits == tv_hdr_lookup)
	{
		switch (role_bits)
		{
			// we are controller
			// it seems good now...
			case tv_role_controller:
				return rmc_ctrler;
				break;
			// we are controllee
			// it doesn't works on some platform with diffrent clients
			case tv_role_controllee:
				return rmc_ctrlee;
				break;
			// we don't known if this is right but it works good now...
			default:
				return rmc_onl;
				break;
		}
	}
	
	return rmc_unknown;
}

int rmcontrol::parse_ms_rdp(uint8_t *buffer, size_t len)
{
	tpkt_hdr_t *tpkt_hdr = reinterpret_cast<tpkt_hdr_t *>(buffer);
	cotp_hdr_t *cotp_hdr = reinterpret_cast<cotp_hdr_t *>(buffer + this->tpkt_hdr_len());
	rdp_hdr_t *rdp_hdr = reinterpret_cast<rdp_hdr_t *>(buffer + this->tpkt_hdr_len() + this->cotp_hdr_len());

	// NOTE: if you found this doesn't work and then get the protocol specification out and inside, and out and inside...
	if (tpkt_hdr->ver == 3 && 
			this->cotp_pdu_translate(cotp_hdr->pdu_type) == cotp_pdu_conn_req && 
				rdp_hdr->type == rdp_nr)
		return rmc_onl;

	return rmc_unknown;
}

int rmcontrol::parse_radmin(uint8_t *buffer, size_t len)
{
	uint32_t hdr_bits = *(uint32_t *)buffer;
	uint16_t act_bits = *(uint16_t *)(buffer + (len - sizeof(act_bits)));

	if (hdr_bits == radmin_hdr_login && act_bits == radmin_act_auth)
		return rmc_onl;
	
	return rmc_unknown;
}

void rmcontrol::save_rdp_result(rmc_session_t* rs)
{
	//printf("in save_rdp_result, action: %d\n", rs->type);
	rs->pro_type = 1701;
	this->save_action_result(rs);
}

void rmcontrol::save_tv_result(rmc_session_t* rs)
{
	//printf("in save_tv_result, action: %d\n", rs->type);
	rs->pro_type = 1702;
	this->save_action_result(rs);
}

void rmcontrol::save_radmin_result(rmc_session_t* rs)
{
	//printf("in save_radmin_result, action: %d\n", rs->type);
	rs->pro_type = 1703;
	this->save_action_result(rs);
}
