#include "ldc_packet_mgr.h"
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
ldc_packet_mgr::ldc_packet_mgr()
{
	m_dns_type[1] = "A";
	m_dns_type[2] = "NS";
	m_dns_type[3] = "MD";
	m_dns_type[4] = "MF";
	m_dns_type[5] = "CNAME";
	m_dns_type[6] = "SOA";
	m_dns_type[7] = "MB";
	m_dns_type[8] = "MG";
	m_dns_type[9] = "MR";
	m_dns_type[10] = "NULL";
	m_dns_type[11] = "WKS";
	m_dns_type[12] = "PTR";
	m_dns_type[13] = "HINFO";
	m_dns_type[14] = "MINFO";
	m_dns_type[15] = "MX";
	m_dns_type[16] = "TXT";
	m_dns_type[0x1c] = "AAAA";
	m_dns_type[41] = "opt";
	m_dns_type[0x64] = "UINFO";
	m_dns_type[0x65] = "UID";
	m_dns_type[0x66] = "GID";
	m_dns_type[0xFF] = "ANY";

	m_dns_type_n["A"] = 1;
	m_dns_type_n["NS"] = 2;
	m_dns_type_n["MD"] = 3;
	m_dns_type_n["MF"] = 4;
	m_dns_type_n["CNAME"] = 5;
	m_dns_type_n["SOA"] = 6;
	m_dns_type_n["MB"] = 7;
	m_dns_type_n["MG"] = 8;
	m_dns_type_n["MR"] = 9;
	m_dns_type_n["NULL"] = 10;
	m_dns_type_n["WKS"] = 11;
	m_dns_type_n["PTR"] = 12;
	m_dns_type_n["HINFO"] = 13;
	m_dns_type_n["MINFO"] = 14;
	m_dns_type_n["MX"] = 15;
	m_dns_type_n["TXT"] = 16;
	m_dns_type_n["AAAA"] = 0x1c;
	m_dns_type_n["OPT"] = 41;
	m_dns_type_n["UINFO"] = 0x64;
	m_dns_type_n["UID"] = 0x65;
	m_dns_type_n["GID"] = 0x66;
	m_dns_type_n["ANY"] = 0xFF;

	m_dns_class[1] = "IN";
	m_dns_class[2] = "CSNET";
	m_dns_class[3] = "CHAOS";
	m_dns_class[4] = "HESIOD";
	m_dns_class[0xFF] = "ANY";

	m_dns_class_n["IN"] = 1;
	m_dns_class_n["CSNET"] = 2;
	m_dns_class_n["CHAOS"] = 3;
	m_dns_class_n["HESIOD"] = 4;
	m_dns_class_n["ANY"] = 0xFF;
}

ldc_packet_mgr::~ldc_packet_mgr()
{

}

unsigned char *ldc_packet_mgr::get_domain(unsigned char *p,unsigned  char *buf, string& str_domain, unsigned int len)
{

        unsigned int nchars,offset;
	unsigned char *ptr;
	char domain[2000];
	memset(domain, 0, 2000);
	if((p-buf+1) > len)
		return buf+len;
        nchars = *(p++);
        if((nchars & 0xc0) == 0xc0)
        {
		if((p-buf+1) > len)
                	return buf+len;
                offset = (nchars & 0x3f) << 8;
                offset |= *(p++);
                ptr = buf + offset;
		get_domain(ptr, buf, str_domain, len);
		
        }
        else if(nchars > 0)
        {
		if(p-buf+nchars > len)
			return buf+len;
		sprintf(domain, "%*.*s",nchars,nchars,p);
		str_domain += domain;
		str_domain += ".";
		if(str_domain.size() > 1000 )
			return buf+len;
                
		p += nchars;
		if(*p != '\0')
		{
			p = get_domain(p, buf, str_domain, len);
		}else
        		p++;
	}
	else
		str_domain = ".";
	if((p-buf+1) > len )
        	return buf + len;
        return p;
}
unsigned char* ldc_packet_mgr::record_parse(unsigned char *p, unsigned char *buf, unsigned int count, unsigned int len)
{
	unsigned int i,j,type=0,qclass=0,ttl,rdlength;
	string str_domain;
//*	
	char a[]="";
	char b[]="";
	char c[]="";
// */
/*
	char a[]="\033[33m";
	char b[]="\033[31m";
	char c[]="\033[0m";
// */
	if(count > 0)
		printf("%sname                                     type   class  ttl    rdlength   data%s\n", a, c);
	for(int i=0; i<count; i++)
	{
		str_domain.clear();
		if((p-buf+1) > len )
                	return buf + len;
		p = get_domain(p,buf,str_domain, len);
		
		if((p-buf+2) > len )
                        return buf+len;
		GETWORD(type,p);
		
		if((p-buf+2) > len )
                        return buf+len;
		GETWORD(qclass,p);
		
		if((p-buf+4) > len )
                        return buf+len;
		GETLONG(ttl,p);

		if((p-buf+2) > len )
                        return buf+len;
		GETWORD(rdlength,p);

		if(type == 1)
		{
			printf("%s%-40s%s", b, str_domain.c_str(), c);
			printf("%s %-7s%s", b, m_dns_type[type].c_str(), c);
			printf("%s%-7s%s", b, m_dns_class[qclass].c_str(), c);
			printf("%s%-7u%s", b, ttl, c);
			printf("%s%-11u%s", b, rdlength, c);

			unsigned int ip = *(unsigned int*)p;
			struct sockaddr_in addr;
			addr.sin_addr.s_addr = ip;
			printf("%s%s%s\n", b, inet_ntoa(addr.sin_addr), c);
			p += rdlength;
		}
		else if(type == 2)
		{
			printf("%s%-40s%s", b, str_domain.c_str(), c);
			printf("%s %-7s%s", b, m_dns_type[type].c_str(), c);
			printf("%s%-7s%s", b, m_dns_class[qclass].c_str(), c);
			printf("%s%-7u%s", b, ttl, c);
			printf("%s%-11u%s", b, rdlength, c);

			str_domain.clear();
			get_domain(p,buf,str_domain, len);
			printf("%s%s%s\n", b, str_domain.c_str(), c);
			p += rdlength;
		}
		else if(type == 5)
		{
			printf("%s%-40s%s", b, str_domain.c_str(), c);
			printf("%s %-7s%s", b, m_dns_type[type].c_str(), c);
			printf("%s%-7s%s", b, m_dns_class[qclass].c_str(), c);
			printf("%s%-7u%s", b, ttl, c);
			printf("%s%-11u%s", b, rdlength, c);
			str_domain.clear();
			get_domain(p,buf,str_domain, len);
			printf("%s%s%s\n", b, str_domain.c_str(), c);
			p += rdlength;
		}
		else if(type == 6)
		{
			printf("%s%-40s%s", b, str_domain.c_str(), c);
			printf("%s %-7s%s", b, m_dns_type[type].c_str(), c);
			printf("%s%-7s%s", b, m_dns_class[qclass].c_str(), c);
			printf("%s%-7u%s", b, ttl, c);
			printf("%s%-11u%s", b, rdlength, c);		
			string server;
			string mail_address;
			unsigned int serial_num;
			unsigned int refresh;
			unsigned int retry;
			unsigned int expire;
			unsigned int ttl;
			str_domain.clear();
			unsigned char* ptr = p;
			ptr = get_domain(ptr,buf,str_domain, len);
			printf("%s%s%s ", b, str_domain.c_str(), c);
			str_domain.clear();
			ptr = get_domain(ptr,buf,str_domain, len);
			printf("%s%s%s ", b, str_domain.c_str(), c);
			//printf("num is %d\n",p+rdlength-ptr);
			//*
			GETLONG(serial_num, ptr);
			GETLONG(refresh, ptr);
			GETLONG(retry, ptr);
			GETLONG(expire, ptr);
			GETLONG(ttl, ptr);
			printf("%s%ld%s ", b, serial_num, c);
			printf("%s%ld%s ", b, refresh, c);
			printf("%s%ld%s ", b, retry, c);
			printf("%s%ld%s ", b, expire, c);
			printf("%s%ld%s ", b, ttl, c);
			// */
			p += rdlength;
		}
		else if(type == 41)
		{
			printf("%s%-40s%s", b, str_domain.c_str(), c);
			printf("%s %-7s%s", b, m_dns_type[type].c_str(), c);
			printf("%s%-7d%s", b, qclass, c);
			printf("%s%-7u%s", b, ttl, c);
			printf("%s%-11u%s\n", b, rdlength, c);
			unsigned short code;
			unsigned short optlen;
			unsigned short optfamily;
			unsigned char source_netmask;
			unsigned char scope_netmask;
			unsigned int   ip;
			printf("%scode  optlen  optfamily  source_netmask  scope_netmask  data%s\n", a, c);
			if(rdlength > 0)
			{
				GETWORD(code,p);
				printf("%s%-6u%s", b, code, c);
				
				GETWORD(optlen,p);
				printf("%s%-8u%s", b, optlen, c);
				
				GETWORD(optfamily,p);
				printf("%s%-11u%s", b, optfamily, c);
				
				source_netmask = *(p++);
				printf("%s%-16u%s", b, source_netmask, c);
				
				scope_netmask = *(p++);
				printf("%s%-15u%s", b, scope_netmask, c);
				
				ip = *(unsigned int*)p;
				struct sockaddr_in addr;
				addr.sin_addr.s_addr = ip;
				printf("%s%s%s\n", b, inet_ntoa(addr.sin_addr), c);
				
				p += optlen -4;
			}
		}
		else
		{
			printf("%s%-40s%s", b, str_domain.c_str(), c);
			map<unsigned int, string>::iterator iter;
                  	iter = m_dns_type.find(type);
                  	if(iter == m_dns_type.end())
                        	printf("%s %-7d%s", b, type, c);
			else
				printf("%s %-7s%s", b, m_dns_type[type].c_str(), c);	
			iter = m_dns_class.find(qclass);
                   	if(iter == m_dns_class.end())
                        	printf("%s%-7d%s", b, qclass, c);
			else
				printf("%s%-7s%s", b, m_dns_class[qclass].c_str(), c);
                        printf("%s%-7u%s", b, ttl, c);
                        printf("%s%-11u%s\n", b, rdlength, c);
			p += rdlength;
		}
	}
	return p;
}
unsigned char* ldc_packet_mgr::parse_dns_packet(unsigned char *buf, unsigned int len)
{
	unsigned char *p;
	unsigned int ident,flags,qdcount,ancount,nscount,arcount;
	unsigned int i,j,type=0,qclass=0,ttl,rdlength;

	//*     
	char a[]="";
	char b[]="";
	char c[]="";
	// */   
	/*
	char a[]="\033[33m";
	char b[]="\033[31m";
	char c[]="\033[0m";
	// */
	p = buf;
	GETWORD(ident,p);

	GETWORD(flags,p);
	printf("%sident   qr  opcode  aa  tc  rd  ra  z  rcode%s\n", a, c);
	printf("%s%#-8x%s", b, ident, c);
	printf("%s%-4u%s", b, flags>>15, c);
	printf("%s%-8u%s", b, (flags>>11)&15, c);
	printf("%s%-4u%s", b, (flags>>10)&1, c);
	printf("%s%-4u%s", b, (flags>>9)&1, c);
	printf("%s%-4u%s", b, (flags>>8)&1, c);
	printf("%s%-4u%s", b, (flags>>7)&1, c);
	printf("%s%-3u%s", b, (flags>>4)&7, c);
	printf("%s%-5u%s\n", b, flags&15, c);
	GETWORD(qdcount,p);
	GETWORD(ancount,p);
	GETWORD(nscount,p);
	GETWORD(arcount,p);
	if(((flags>>4)&7) != 0)
		return buf+len;
	if((flags&15) ==1)
		return buf+len;
	if((p-buf+1) >= len )
		return buf+len;
	printf("\n%sQUESTION SECTION:%s%s %u%s\n", a, c, b, qdcount, c);
	printf("%sname                                    type   class%s\n", a, c);
	for(i=0; i<qdcount; i++)
	{
		string str_domain;
		p = get_domain(p,buf,str_domain, len);
		
		printf("%s%-40s%s", b, str_domain.c_str(), c);
		GETWORD(type,p);
		map<unsigned int, string>::iterator iter;
       		iter = m_dns_type.find(type);
		if(iter == m_dns_type.end())
			printf("%s %-7d%s", b, type, c);
		else
			printf("%s %-7s%s", b, m_dns_type[type].c_str(), c);

		GETWORD(qclass,p);
		iter = m_dns_class.find(qclass);
		if(iter == m_dns_class.end())
			printf("%s%-7d%s\n", b, qclass, c);
		else
			printf("%s%-7s%s\n", b, m_dns_class[qclass].c_str(), c);

	}
	printf("\n%sANSWER SECTION:%s%s %u%s\n", a, c, b, ancount, c);
	p = record_parse(p, buf, ancount, len);
	
	printf("\n%sAUTHORITY SECTION:%s%s %u%s\n", a, c, b, nscount, c);
	p = record_parse(p, buf, nscount, len);
	
	printf("\n%sADDITIONAL SECTION:%s%s %u%s\n", a, c, b, arcount, c);
	p = record_parse(p, buf, arcount, len);
	return p;
	
}
int ldc_packet_mgr::create_packet(char* buffer, int buffer_size, char* domain, unsigned int client_ip, string& type)
{
	
	if(domain[strlen(domain)-1] == '.')
		domain[strlen(domain)-1] = '\0';
	m_total_len  = sizeof(ldc_dns_header) + strlen(domain) + 2 + sizeof(ldc_query_hdr) ;
	if (!buffer || buffer_size<m_total_len){
		return -1;
	}
	set_dns_header(client_ip);
	set_dns_query(type,"IN");
	
	if(client_ip > 0)
		set_edns(client_ip);
    	memset(buffer, 0, strlen(buffer));
	memcpy( buffer, (void*)&m_dns_header, sizeof(m_dns_header));
	add_domain(buffer + sizeof(m_dns_header), domain);
	memcpy( buffer + sizeof(m_dns_header) + strlen(domain) + 2, (void*)&m_query_header, sizeof(m_query_header));
	if(client_ip > 0)
	{
		printf("ends_client_subnet!\n");
		unsigned char a = 0 ;
		memcpy( buffer + sizeof(m_dns_header) + strlen(domain) + 2 + sizeof(m_query_header), (void*)&a, 1);
		memcpy( buffer + sizeof(m_dns_header) + strlen(domain) + 2 + sizeof(m_query_header) + 1, (void*)&m_rr, sizeof(m_rr));
		unsigned short rdlen = 0x0c00;
		memcpy( buffer + sizeof(m_dns_header) + strlen(domain) + 2 + sizeof(m_query_header) + 1 + sizeof(m_rr) , (void*)&rdlen, 2);
		memcpy( buffer + sizeof(m_dns_header) + strlen(domain) + 2 + sizeof(m_query_header) + 3 + sizeof(m_rr), (void*)&m_edns, sizeof(m_edns));
		m_total_len +=  1 + sizeof(m_rr)  + sizeof(m_edns) + 2;
	}
	return m_total_len;
}


void ldc_packet_mgr::set_dns_header(unsigned int client_ip)
{
    srand(time(0));
	m_dns_header.tid = rand() % 40000 + 12345;
	m_tid = ntohs(m_dns_header.tid);
	m_dns_header.flags = 0x0001;
	m_dns_header.queries = 0x0100;
	m_dns_header.answers = 0x0000;
	m_dns_header.auth = 0x0000;
	if(client_ip > 0)
		m_dns_header.additional = 0x0100;
	else
		m_dns_header.additional = 0x0000;
}

void ldc_packet_mgr::set_dns_query(string qtype, string qclass)
{
	unsigned short qtype_n = 0, qclass_n = 0;
	map<string, unsigned int>::iterator iter;
	iter = m_dns_type_n.find(qtype);
	if(iter == m_dns_type_n.end())
		qtype_n = 1;
	else
		qtype_n = m_dns_type_n[qtype];

	iter = m_dns_class_n.find(qclass);
	if(iter == m_dns_class_n.end())
		qclass_n = 1;
	else
		qclass_n = m_dns_class_n[qclass];
	m_query_header.type = 0;
        m_query_header.type |= qtype_n >> 8;
        m_query_header.type |= (qtype_n & 0x00FF) << 8;
	m_query_header.qclass = 0;
	m_query_header.qclass |= qclass_n >> 8;
	m_query_header.qclass |= (qclass_n & 0x00FF) << 8;
}
void ldc_packet_mgr::set_edns(unsigned int client_ip)
{
	m_rr.type = 0x2900;
	m_rr.qclass = 0x0010;
	m_rr.hb_rcode = 0x0;
	m_rr.edns0_ver = 0;
	m_rr.z = 0;
	m_edns.opt_code = 0x0800;
	m_edns.opt_len = 0x0800;
	m_edns.opt_family = 0x0100;
	m_edns.source_netmask = 0x20;
	m_edns.scope_netmask = 0x00;
	m_edns.opt_address = client_ip;

}

int ldc_packet_mgr::add_domain( char *buffer, char *base_name )
{
	char *tmp = (char *)malloc(strlen(base_name)+1);
	if( NULL == tmp )
	{
		return -1;
	}
	memset( tmp, 0, strlen(base_name)+1 );
	memset(m_query_domain, 0, sizeof(m_query_domain));
	if (base_name[0] == '.') {
		sprintf(tmp, "%c%c%c%s", rand()%25+97, rand()%25+97, rand()%25+97, base_name );
	} else {
		strncpy(tmp, base_name, strlen(base_name));
	}
	strncpy(m_query_domain, tmp, sizeof(m_query_domain));

	int length_pos = 0;
	int loop_num = 1;

	char *token = strtok( tmp, "." );
	while( NULL != token )
	{
		if( loop_num == 1 )
		{
			length_pos = 0;
			memset( buffer, strlen(token), 1 );
			strcpy( buffer+length_pos+1, token );
			length_pos = length_pos + strlen(token) + 1;
		}
		else
		{
			memset( buffer+length_pos, strlen(token), 1 );
			strcpy( buffer+length_pos+1, token );
			length_pos = length_pos + strlen(token) + 1;
		}

		token = strtok( NULL, "." );
		loop_num ++;
	}
	free(tmp);
}


int ldc_packet_mgr::modify_packet_value( char* buffer,ldc_en_key key, void* value )
{
	int len=0;
	switch(key)
	{
		case EN_DOMAIN:
		{
			char* name = (char*)value;
			memset(buffer+12, 0, m_total_len-12);
			add_domain(buffer+12, (char*)value);
			memcpy( buffer+12+strlen((char*)value)+2, ((char*)&m_query_header), 4);
			unsigned char a = 0 ;
			memcpy( buffer + sizeof(m_dns_header) + strlen(name) + 2 + sizeof(m_query_header), (void*)&a, 1);
			memcpy( buffer + sizeof(m_dns_header) + strlen(name) + 2 + sizeof(m_query_header) + 1, (void*)&m_rr, sizeof(m_rr));
			unsigned short rdlen = 0x0c00;
			memcpy( buffer + sizeof(m_dns_header) + strlen(name) + 2 + sizeof(m_query_header) + 1 + sizeof(m_rr) , (void*)&rdlen, 2);
			memcpy( buffer + sizeof(m_dns_header) + strlen(name) + 2 + sizeof(m_query_header) + 3 + sizeof(m_rr), (void*)&m_edns, sizeof(m_edns));
			m_total_len = sizeof(m_dns_header) + strlen(name) + 2 + sizeof(m_query_header) + 3 + sizeof(m_rr) + sizeof(m_edns);
			break;
		}
		case EN_EDNS_CLIENT_IP:
		{
			unsigned int client = *(unsigned int*)value;
			m_edns.opt_address = client;
			memcpy( buffer + m_total_len - sizeof(m_edns), (void*)&m_edns, sizeof(m_edns));
			break;
		}
		default :
			break;
	}
	return m_total_len;
}
