#ifndef _H_INCLUDE_LOC_PACKET_MGR_
#define _H_INCLUDE_LOC_PACKET_MGR_

#include <string.h>
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include "ldc_define.h"

using namespace std;

class ldc_packet_mgr
{
public:
	ldc_packet_mgr();
	~ldc_packet_mgr();
	int create_packet(char* buffer, int buffer_size, char* domain, unsigned int client_ip, string& type);
	int modify_packet_value(char* buffer, ldc_en_key key, void* value);
	unsigned char* parse_dns_packet(unsigned char *buf, unsigned int len);
private:
	void set_dns_header(unsigned int client_ip);
	void set_dns_query(string qtype, string qclass);
	void set_edns(unsigned int client_ip);
	int  add_domain( char *buffer, char *base_name );
	unsigned char* record_parse(unsigned char *p, unsigned char *buf, unsigned int count, unsigned int len);
	unsigned char *get_domain(unsigned char *p,unsigned  char *buf, string& str_domain, unsigned int len);
	
private:
	
	ldc_dns_header  m_dns_header;
	ldc_query_hdr   m_query_header;
	ldc_rr		m_rr;
	ldc_edns	m_edns;
	map<string, unsigned int> m_dns_type_n;
	map<string, unsigned int> m_dns_class_n;
	map<unsigned int, string> m_dns_type;
	map<unsigned int, string> m_dns_class;

    int             m_total_len;
	int             m_tid;
	char m_query_domain[256];
};
#endif //_H_INCLUDE_LOC_PACKET_MGR_
