#ifndef _H_LDC_DEFINE_H 
#define _H_LDC_DEFINE_H
#define MAXDATASIZE 1024
#define GETWORD(__w,__p) do{__w=*(__p++)<<8;__w|=*(p++);}while(0)
#define GETLONG(__l,__p) do{__l=*(__p++)<<24;__l|=*(__p++)<<16;__l|=*(__p++)<<8;__l|=*(p++);}while(0)
typedef struct ip_info
{
	unsigned int ipstart;
	unsigned int ipend;
}ldc_ip_info;

typedef struct dns_hdr
{
	unsigned short    tid;
	unsigned short    flags;
	unsigned short    queries;
	unsigned short    answers;
	unsigned short    auth;
	unsigned short    additional;
}ldc_dns_header;

typedef struct query_hdr
{
	unsigned short    type;
	unsigned short    qclass;
}ldc_query_hdr;

typedef struct rr
{
	unsigned short    type;
	unsigned short    qclass;
	unsigned char hb_rcode;

	unsigned char edns0_ver;

	unsigned short z;
}ldc_rr;

typedef struct ends
{
	unsigned short opt_code;
	unsigned short opt_len;
	unsigned short opt_family;
	unsigned char  source_netmask;
	unsigned char scope_netmask;
	unsigned int opt_address;
}ldc_edns;

typedef enum keys
{
    EN_EDNS_CLIENT_IP,
    EN_SRC_IP,
	EN_DEST_IP,
	EN_DOMAIN
}ldc_en_key;

#endif //_H_LDC_DEFINE_H
