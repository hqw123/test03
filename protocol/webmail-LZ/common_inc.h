#ifndef COMMEN_H
#define COMMEN_H

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdlib.h>

#include "PacketParser.h"


int analyse_sina(void *tmp,char *data,unsigned int datalen, struct tcphdr *tcp,int is_b_s,int mora);
void analyse_21cn(void *tmp,char *data ,unsigned int datalen,struct tcphdr *tcp , int is_b_s,int mora);
void analyse_sohu(PacketInfo * packetInfo, void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora);
int analyse_163(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_hotmail(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_yahoo(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_tom(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
void  analyse_yeah(void *node,char *data,unsigned int data_len,struct tcphdr *ptcp,int is_to_s,int m_or_a);
void analyse_eyou(void *tmp,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s,int mora);
void analyse_263(void *tmp,char *data, unsigned int datalen,struct tcphdr *tcp, int is_b_s,int mora);
int analyse_qq(PacketInfo * packetInfo, void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
void analyse_sogou(PacketInfo *packetInfo, void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora);
int analyse_126(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_188(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
void analyse_gmail(void *tmp, char *data, unsigned int datalen, struct tcphdr *tcp, int is_b_s, int mora);
void analyse_mail(void *tmp,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s,int m_or_a);
void analyse_aol(PacketInfo * packetInfo, void *tmp,char *data,unsigned int datalen,struct tcphdr *tcp,int is_b_s,int m_or_a,char *destMAC);
int analyse_hanmail(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_139(PacketInfo *packetInfo, void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_2980(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_189(PacketInfo * packetInfo,void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_m_163(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);
int analyse_m_qq(void *node, char *data, unsigned int data_len, struct tcphdr *ptcp, int is_to_s, int m_or_a);

#endif

