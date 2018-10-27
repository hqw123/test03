#include "PacketInfo.h"

char* ParseMac(const u_char* packet, char* mac)
{
    //assert((packet || mac) != 0);
 	if (packet == NULL || mac == NULL)
		return NULL;
	
    sprintf(mac, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\0", 
            *reinterpret_cast<const u_char*>(packet),
            *reinterpret_cast<const u_char*>(packet + 1),
            *reinterpret_cast<const u_char*>(packet + 2),
            *reinterpret_cast<const u_char*>(packet + 3),
            *reinterpret_cast<const u_char*>(packet + 4),
            *reinterpret_cast<const u_char*>(packet + 5));

    return mac;
}

