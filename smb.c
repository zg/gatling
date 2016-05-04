#define _FILE_OFFSET_BITS 64
#define _BSD_SOURCE
#include "gatling.h"

#ifdef SUPPORT_SMB

#include "byte.h"
#include "rangecheck.h"
#include "str.h"

#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <iconv.h>
#include <sys/statvfs.h>
#include <fnmatch.h>
#include <dirent.h>
#include <ctype.h>

#include <stdio.h>

#include "havealloca.h"

/* very offensive, I know.  The idea is that gcc evaluates this at
 * compile time if buf and x are const char.  So I'm using this instead
 * of counting the offsets manually, so you don't have to count anything
 * if you want to follow the code and see what it does. */


#define OFS16(buf,x) \
  ((sizeof(buf)>0+1 && buf[0]==x[0] && buf[0+1]==x[1])?0: \
  ((sizeof(buf)>1+1 && buf[1]==x[0] && buf[1+1]==x[1])?1: \
  ((sizeof(buf)>2+1 && buf[2]==x[0] && buf[2+1]==x[1])?2: \
  ((sizeof(buf)>3+1 && buf[3]==x[0] && buf[3+1]==x[1])?3: \
  ((sizeof(buf)>4+1 && buf[4]==x[0] && buf[4+1]==x[1])?4: \
  ((sizeof(buf)>5+1 && buf[5]==x[0] && buf[5+1]==x[1])?5: \
  ((sizeof(buf)>6+1 && buf[6]==x[0] && buf[6+1]==x[1])?6: \
  ((sizeof(buf)>7+1 && buf[7]==x[0] && buf[7+1]==x[1])?7: \
  ((sizeof(buf)>8+1 && buf[8]==x[0] && buf[8+1]==x[1])?8: \
  ((sizeof(buf)>9+1 && buf[9]==x[0] && buf[9+1]==x[1])?9: \
  ((sizeof(buf)>10+1 && buf[10]==x[0] && buf[10+1]==x[1])?10: \
  ((sizeof(buf)>11+1 && buf[11]==x[0] && buf[11+1]==x[1])?11: \
  ((sizeof(buf)>12+1 && buf[12]==x[0] && buf[12+1]==x[1])?12: \
  ((sizeof(buf)>13+1 && buf[13]==x[0] && buf[13+1]==x[1])?13: \
  ((sizeof(buf)>14+1 && buf[14]==x[0] && buf[14+1]==x[1])?14: \
  ((sizeof(buf)>15+1 && buf[15]==x[0] && buf[15+1]==x[1])?15: \
  ((sizeof(buf)>16+1 && buf[16]==x[0] && buf[16+1]==x[1])?16: \
  ((sizeof(buf)>17+1 && buf[17]==x[0] && buf[17+1]==x[1])?17: \
  ((sizeof(buf)>18+1 && buf[18]==x[0] && buf[18+1]==x[1])?18: \
  ((sizeof(buf)>19+1 && buf[19]==x[0] && buf[19+1]==x[1])?19: \
  ((sizeof(buf)>20+1 && buf[20]==x[0] && buf[20+1]==x[1])?20: \
  ((sizeof(buf)>21+1 && buf[21]==x[0] && buf[21+1]==x[1])?21: \
  ((sizeof(buf)>22+1 && buf[22]==x[0] && buf[22+1]==x[1])?22: \
  ((sizeof(buf)>23+1 && buf[23]==x[0] && buf[23+1]==x[1])?23: \
  ((sizeof(buf)>24+1 && buf[24]==x[0] && buf[24+1]==x[1])?24: \
  ((sizeof(buf)>25+1 && buf[25]==x[0] && buf[25+1]==x[1])?25: \
  ((sizeof(buf)>26+1 && buf[26]==x[0] && buf[26+1]==x[1])?26: \
  ((sizeof(buf)>27+1 && buf[27]==x[0] && buf[27+1]==x[1])?27: \
  ((sizeof(buf)>28+1 && buf[28]==x[0] && buf[28+1]==x[1])?28: \
  ((sizeof(buf)>29+1 && buf[29]==x[0] && buf[29+1]==x[1])?29: \
  ((sizeof(buf)>30+1 && buf[30]==x[0] && buf[30+1]==x[1])?30: \
  ((sizeof(buf)>31+1 && buf[31]==x[0] && buf[31+1]==x[1])?31: \
  ((sizeof(buf)>32+1 && buf[32]==x[0] && buf[32+1]==x[1])?32: \
  ((sizeof(buf)>33+1 && buf[33]==x[0] && buf[33+1]==x[1])?33: \
  ((sizeof(buf)>34+1 && buf[34]==x[0] && buf[34+1]==x[1])?34: \
  ((sizeof(buf)>35+1 && buf[35]==x[0] && buf[35+1]==x[1])?35: \
  ((sizeof(buf)>36+1 && buf[36]==x[0] && buf[36+1]==x[1])?36: \
  ((sizeof(buf)>37+1 && buf[37]==x[0] && buf[37+1]==x[1])?37: \
  ((sizeof(buf)>38+1 && buf[38]==x[0] && buf[38+1]==x[1])?38: \
  ((sizeof(buf)>39+1 && buf[39]==x[0] && buf[39+1]==x[1])?39: \
  ((sizeof(buf)>40+1 && buf[40]==x[0] && buf[40+1]==x[1])?40: \
  ((sizeof(buf)>41+1 && buf[41]==x[0] && buf[41+1]==x[1])?41: \
  ((sizeof(buf)>42+1 && buf[42]==x[0] && buf[42+1]==x[1])?42: \
  ((sizeof(buf)>43+1 && buf[43]==x[0] && buf[43+1]==x[1])?43: \
  ((sizeof(buf)>44+1 && buf[44]==x[0] && buf[44+1]==x[1])?44: \
  ((sizeof(buf)>45+1 && buf[45]==x[0] && buf[45+1]==x[1])?45: \
  ((sizeof(buf)>46+1 && buf[46]==x[0] && buf[46+1]==x[1])?46: \
  ((sizeof(buf)>47+1 && buf[47]==x[0] && buf[47+1]==x[1])?47: \
  ((sizeof(buf)>48+1 && buf[48]==x[0] && buf[48+1]==x[1])?48: \
  ((sizeof(buf)>49+1 && buf[49]==x[0] && buf[49+1]==x[1])?49: \
  ((sizeof(buf)>50+1 && buf[50]==x[0] && buf[50+1]==x[1])?50: \
  ((sizeof(buf)>51+1 && buf[51]==x[0] && buf[51+1]==x[1])?51: \
  ((sizeof(buf)>52+1 && buf[52]==x[0] && buf[52+1]==x[1])?52: \
  ((sizeof(buf)>53+1 && buf[53]==x[0] && buf[53+1]==x[1])?53: \
  ((sizeof(buf)>54+1 && buf[54]==x[0] && buf[54+1]==x[1])?54: \
  ((sizeof(buf)>55+1 && buf[55]==x[0] && buf[55+1]==x[1])?55: \
  ((sizeof(buf)>56+1 && buf[56]==x[0] && buf[56+1]==x[1])?56: \
  ((sizeof(buf)>57+1 && buf[57]==x[0] && buf[57+1]==x[1])?57: \
  ((sizeof(buf)>58+1 && buf[58]==x[0] && buf[58+1]==x[1])?58: \
  ((sizeof(buf)>59+1 && buf[59]==x[0] && buf[59+1]==x[1])?59: \
  ((sizeof(buf)>60+1 && buf[60]==x[0] && buf[60+1]==x[1])?60: \
  ((sizeof(buf)>61+1 && buf[61]==x[0] && buf[61+1]==x[1])?61: \
  ((sizeof(buf)>62+1 && buf[62]==x[0] && buf[62+1]==x[1])?62: \
  ((sizeof(buf)>63+1 && buf[63]==x[0] && buf[63+1]==x[1])?63: \
  ((sizeof(buf)>64+1 && buf[64]==x[0] && buf[64+1]==x[1])?64: \
  ((sizeof(buf)>65+1 && buf[65]==x[0] && buf[65+1]==x[1])?65: \
  ((sizeof(buf)>66+1 && buf[66]==x[0] && buf[66+1]==x[1])?66: \
  ((sizeof(buf)>67+1 && buf[67]==x[0] && buf[67+1]==x[1])?67: \
  ((sizeof(buf)>68+1 && buf[68]==x[0] && buf[68+1]==x[1])?68: \
  ((sizeof(buf)>69+1 && buf[69]==x[0] && buf[69+1]==x[1])?69: \
  ((sizeof(buf)>70+1 && buf[70]==x[0] && buf[70+1]==x[1])?70: \
  ((sizeof(buf)>71+1 && buf[71]==x[0] && buf[71+1]==x[1])?71: \
  ((sizeof(buf)>72+1 && buf[72]==x[0] && buf[72+1]==x[1])?72: \
  ((sizeof(buf)>73+1 && buf[73]==x[0] && buf[73+1]==x[1])?73: \
  ((sizeof(buf)>74+1 && buf[74]==x[0] && buf[74+1]==x[1])?74: \
  ((sizeof(buf)>75+1 && buf[75]==x[0] && buf[75+1]==x[1])?75: \
  ((sizeof(buf)>76+1 && buf[76]==x[0] && buf[76+1]==x[1])?76: \
  ((sizeof(buf)>77+1 && buf[77]==x[0] && buf[77+1]==x[1])?77: \
  ((sizeof(buf)>78+1 && buf[78]==x[0] && buf[78+1]==x[1])?78: \
  ((sizeof(buf)>79+1 && buf[79]==x[0] && buf[79+1]==x[1])?79: \
  -1))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))


#if 0
               _
 ___ _ __ ___ | |__
/ __| '_ ` _ \| '_ \
\__ \ | | | | | |_) |
|___/_| |_| |_|_.__/
#endif

#if 0
struct smbheader {
  unsigned char protocol[4];	/* '\xffSMB' */
  unsigned char command;	/* command code */
  unsigned long status;
  unsigned char flags;
  unsigned short flags2;
  union {
    unsigned short pad[6];
    struct {
      unsigned short pidhigh;
      unsigned char securitysignature[8];
    } extra;
  };
  unsigned char reserved[2];
  unsigned short tid;	/* tree identifier */
  unsigned short pid;	/* caller's process id */
  unsigned short uid;	/* user id */
  unsigned short mid;	/* multiplex id */
  /* first:
  unsigned char wordcount;	// count of parameter words
  unsigned short parameterwords[1];
  */
  /* then:
   unsigned short bytecount;
   unsigned char buf[bytecount];
   */
};
#endif

static int globmatch_int(const char* pattern,const char* string,const char* ldot) {
  while (*pattern) {
    switch (*pattern) {
    case '?':
      if (!*string) return *pattern==0;
      break;
    case '<':
      if (string>ldot)
	return 0;
    case '*':
      /* pattern="*.x" and string=".x"? */
      if (globmatch_int(pattern+1,string,ldot)) return 1;
      /* pattern="*.x" and string="a.x"? */
      if (*string==0) return 0;
      ++string;
      continue;
    default:
      if (tolower(*string) != tolower(*pattern)) return 0;
      if (!*string) return 1;
    }
    ++pattern;
    ++string;
  }
  return *string==0;
}

static int globmatch(const char* pattern,const char* string) {
  const char* ldot=strrchr(string,'.');
  if (!ldot) ldot=string+strlen(string);
  return globmatch_int(pattern,string,ldot);
}

static int hasandx(unsigned char code) {
  return !strchr("\x04\x72\x71\x2b\x32\x80\xa0\x23",code);
}

static const size_t netbiosheadersize=4;
static const size_t smbheadersize=32;

struct smb_response {
  char* buf;
  size_t allocated,used,andxtypeofs;
};

#ifdef DEBUG
static void hexdump(char* buf,size_t len) {
  size_t i,j;
  char y[17];
  y[16]=0;
//  printf("sending:\n");
  for (i=j=0; i<len; ++i) {
    if (j==16) j=0;
    y[j]=buf[i];
    if (y[j]<' ' || y[j]==0x7f) y[j]='.';
    ++j;
    printf("%02x",(unsigned char)(buf[i]));
    switch (i%16) {
    case 15: printf("   %s\n",y); break;
    case 7: putchar(' ');	// fallthrough
    default: putchar(' '); break;
    }
  }
  y[j]=0;
  if (j<16)
    printf("%*s%s\n",(int)((17-j)*3)-1,"",y);
}
#endif

static int init_smb_response(struct smb_response* sr,unsigned char* in_response_to,size_t size) {
  if (size<200) size=200;
  sr->buf=malloc(sr->allocated=size);
  if (!sr->buf) return -1;

  sr->used=netbiosheadersize+smbheadersize;

  uint32_pack_big(sr->buf,32);	// size field in NMB header
  byte_copy(sr->buf+netbiosheadersize,smbheadersize-8,
	    "\xffSMB"	// magic
	    "x"		// smb command, filled in later; ofs 4
	    "\x00\x00\x00\x00"	// STATUS_SUCCESS
	    "\x80"	// Flags: response+case sensitive
	    "\x41\xc0"	// Flags2: unicode+long names allowed
	    "\x00\x00"	// Process ID High: 0
	    "\x00\x00\x00\x00\x00\x00\x00\x00"	// Signature
	    "\x00\x00"	// Reserved
	   );		// TID, PID, UID, MID; ofs 24

  sr->buf[netbiosheadersize+4]=in_response_to[4];
  uint16_pack(sr->buf+netbiosheadersize+24,uint16_read((char*)in_response_to+24));
  uint16_pack(sr->buf+netbiosheadersize+26,uint16_read((char*)in_response_to+26));
  uint16_pack(sr->buf+netbiosheadersize+28,0);
  uint16_pack(sr->buf+netbiosheadersize+30,uint16_read((char*)in_response_to+30));

  sr->andxtypeofs=netbiosheadersize+4;

  return 0;
}

static int add_smb_response(struct smb_response* sr,const char* buf,size_t size,unsigned char type) {
  if (sr->allocated+size<size) return -1;	// check int overflow
  if (sr->used+size>sr->allocated) {
    size_t n=sr->allocated+size;
    void* x;
    n=((n-1)|0xfff)+1;		// round up to multiple of 0x1000
    if (!n) return -1;		// check int overflow
    x=realloc(sr->buf,n);
    if (!x) return -1;
    sr->buf=x;
    sr->allocated=n;
  }
  sr->buf[sr->andxtypeofs]=type;
  if (sr->andxtypeofs!=netbiosheadersize+4)
    uint16_pack(sr->buf+sr->andxtypeofs+2,sr->used-netbiosheadersize);
  byte_copy(sr->buf+sr->used,size,buf);
  sr->andxtypeofs=sr->used+1;
  sr->used+=size;
  if (sr->used%2)
    sr->buf[++sr->used]=0;
  uint32_pack_big(sr->buf,sr->used-4);	// update netbios size field
  return 0;
}

static char* add_smb_response2(struct smb_response* sr,const char* buf,size_t size,unsigned char type) {
  size_t i=sr->used;
  if (add_smb_response(sr,buf,size,type)==-1) return 0;
  return sr->buf+i;
}

static void set_smb_error(struct smb_response* sr,uint32_t error,unsigned char req) {
  add_smb_response(sr,"\x00\x00",3,req);
  assert(sr->allocated>=0x20);
  uint32_pack(sr->buf+4+5,error);
}

static int validate_smb_packet(unsigned char* pkt,unsigned long len) {
  /* we actually received len bytes from the wire, so pkt+len does not
   * overflow; we got len bytes, because the netbios header said there
   * were that many bytes in the packet. */
  unsigned char* x;
  /* demand that we have at least a full smbheader and wordcount */
  if (len>=smbheadersize+1 &&
      byte_equal(pkt,4,"\xffSMB")) {	/* signature needs to be there */
    x=(unsigned char*)pkt+smbheadersize;
    if (x[0] > 100)
      return -1;
    /* see that x + sizeof(word_count) + word_count*2 +
     * sizeof(byte_count) is inside the packet */
    if (!range_arrayinbuf(pkt,len,x+3,*x,2))
      return -1;
    /* now we know the word count is ok, but is the byte count? */
    {
      size_t bytecountofs=1+*x*2;
      size_t bytecount;
      bytecount=uint16_read((const char*)x+bytecountofs);
      if (bytecount>len || x+bytecountofs+2+bytecount>pkt+len) return -1;
    }
    if (!hasandx(pkt[4])) return 0;
    for (;;) {
      size_t bytecount;
      /* see that x + sizeof(word_count) + word_count*2 +
      * sizeof(byte_count) is inside the packet */
      if (!range_arrayinbuf(pkt,len,x+3,*x,2))
	return -1;
      /* we know that the byte count is within the packet */
      /* read it and check whether it's ok, too */
      bytecount=uint16_read((const char*)x+1+*x*2);
      if (!range_arrayinbuf(pkt,len,x+3+bytecount,*x,2))
	return -1;
      if (x[1]==0xff) return 0;
      {
	uint16_t next=uint16_read((char*)x+3);
	if (pkt+next < x+1+x[0]*2+2+bytecount) return -1;	/* can't point backwards */
	x=pkt+next;
      }
      if (!range_bufinbuf(pkt,len,(char*)x,5))
	return -1;
    }
  } else
    return -1;
  return 0;
}

static int smb_handle_SessionSetupAndX(unsigned char* pkt,unsigned long len,struct smb_response* sr) {
  const char nr[]=
    "\x03"	// Word Count 3
    "\xff"	// AndXCommand
    "\x00"	// Reserved
    "xx"	// AndXOffset; ofs 3
    "\x01\x00"	// Action: logged in as GUEST
    "xx"	// Byte Count; ofs 7
    "\x00"	// bizarre padding byte
    "U\x00n\x00i\x00x\x00\x00\x00"	// "Unix"
    "G\x00""a\x00t\x00l\x00i\x00n\x00g\x00 \x00";

  size_t i,payloadlen;
  char* x;

  if (len<2*13 || pkt[0] != 13) return -1;	/* word count for this message is always 13 */

  payloadlen=sizeof("Unix_" RELEASE)*2 + wglen16 + 1;

  if (!(x=add_smb_response2(sr,nr,8+payloadlen,0x73))) return -1;

  uint16_pack(x+3,sr->used+2*3+payloadlen);
  uint16_pack(x+7,payloadlen);

  /* should be zero filled already so we only write the even bytes */
  for (i=0; i<sizeof(RELEASE)-sizeof("Gatling ")+1; ++i) {
    x[8+2+(sizeof("Unix_Gatling")+i)*2]=VERSION[i];
    x[8+2+(sizeof("Unix_Gatling")+i)*2+1]=0;
  }

  byte_copy(x+8+2+(sizeof("Unix_Gatling")+i)*2,wglen16+2,workgroup_utf16);

  return 0;
}

static struct timezone tz;

static void uint64_pack_ntdate(char* dest,time_t date) {
  uint64_pack(dest,10000000ll * (date + 11644473600ll));
}

static int smb_handle_negotiate_request(unsigned char* c,size_t len,struct smb_response* sr) {
  size_t i,j,k;
  int ack;
  const char nr[2*17+100*2]=
    "\x11"	// word count 17
    "xx"	// dialect index; ofs 1
    "\x02"	// security mode, for NT: plaintext passwords XOR unicode
#if 0
    "\x02\x00"	// Max Mpx Count 2
    "\x01\x00"	// Max VCs 1
#else
    "\x10\x00"	// Max Mpx Count 16
    "\x10\x00"	// Max VCs 16
#endif
    "\x04\x41\x00\x00"	// Max Buffer Size (16644, like XP)
    "\x00\x00\x01\x00"	// Max Raw Buffer (65536, like XP)
    "\x01\x02\x03\x04"	// Session Key
    "\x5e\x40\x00\x00"	// Capabilities, the bare minimum
    "xxxxxxxx"	// system time; ofs 24
    "xx"	// server time zone; ofs 32
    "\x00"	// key len
    "xx"	// byte count; ofs 35
    ;		// workgroup name; ofs 37
  char* x;

  if (len<3) return -1;
  j=uint16_read((char*)c+1);
  if (len<3+j) return -1;
  ack=-1;
  for (k=0,i=3; i<3+j; ++k) {
    if (c[i]!=2) return -1;
    if (str_equal((char*)c+i+1,"NT LM 0.12")) { ack=k; break; }
    i+=2+str_len((char*)c+i+1);
  }
  if (ack==-1) return -1;	// wrong dialect

  if (!(x=add_smb_response2(sr,nr,38+wglen16,0x72))) return -1;
  uint16_pack(x+1,ack);

  {
    struct timeval t;
    unsigned long long ntdate;
    gettimeofday(&t,&tz);
    ntdate=10000000ll * ( t.tv_sec + 11644473600ll ) + t.tv_usec * 10ll;
    uint32_pack(x+24,ntdate&0xffffffff);
    uint32_pack(x+24+4,ntdate>>32);
    uint16_pack(x+32,tz.tz_minuteswest);
  }

  uint16_pack(x+35,wglen16);
  byte_copy(x+37,wglen16,workgroup_utf16);

  return 0;
}

static int smb_handle_TreeConnectAndX(unsigned char* c,size_t len,struct smb_response* sr) {
  const char nr[]=
    "\x03"	// Word Count 3
    "\xff"	// AndXCommand
    "\x00"	// Reserved
    "\x38\x00"	// AndXOffset; ofs 3
    "\x00\x00"	// Optional Support: none
    "\x0d\x00"	// Byte Count; ofs 7
    "A:\x00"	// "Service", this is what Samba puts there
    "e\x00x\x00t\x00""3\x00\x00\x00";	// "Native Filesystem"
  if (len<2*4 || c[0] != 4) return -1;	/* word count for this message is always 4 */

  return add_smb_response(sr,nr,9+13,0x75);
}

static int smb_handle_echo(unsigned char* c,size_t len,struct smb_response* sr) {
  uint16 nmemb,membsize;
  char* buf;
  size_t i;
  if (len<2*1 || c[0] != 1) return -1;	/* word count for this message is always 1 */
  nmemb=uint16_read((char*)c+1);
  membsize=uint16_read((char*)c+3);
  if (nmemb*membsize>1024) return -1;
  buf=alloca(nmemb*membsize+3);
  buf[0]=0;
  uint16_pack(buf+1,nmemb*membsize);
  for (i=0; i<nmemb; ++i)
    byte_copy(buf+3+i*membsize,membsize,c+5);
  return add_smb_response(sr,buf,nmemb*membsize+3,0x2b);
}

static int smb_handle_TreeDisconnect(unsigned char* c,size_t len,struct smb_response* sr) {
  if (len<3 || c[0]!=0 || c[1]!=0 || c[2]!=0) return -1;	/* word count for this message is always 0 */
  return add_smb_response(sr,(char*)c,3,0x71);
}

iconv_t wc2utf8;
iconv_t utf82wc2;

enum {
  STATUS_INVALID_HANDLE=0xC0000008,
  ERROR_NO_MEMORY=0xc0000017,
  ERROR_ACCESS_DENIED=0xC0000022,
  STATUS_OBJECT_NAME_INVALID=0xC0000033,
  ERROR_OBJECT_NAME_NOT_FOUND=0xc0000034,
  ERROR_NOT_SUPPORTED=0xc00000bb,
  ERROR_NETWORK_ACCESS_DENIED=0xc00000ca,
  STATUS_TOO_MANY_OPENED_FILES=0xC000011F,
};

enum smb_open_todo {
  WANT_OPEN,
  WANT_STAT,
  WANT_CHDIR,
};

/* ssize is the size in bytes, including L'\0' */
/* returns number of converted chars in dest, including \0, or 0 on error */
static size_t utf16tolatin1(char* dest,size_t dsize,uint16_t* src,size_t ssize) {
  size_t i;
  size_t max=dsize;
  if (ssize/2<max) max=ssize/2;
  for (i=0; i<max; ++i) {
    uint16_t x=uint16_read((char*)&src[i]);
    if (x>0xff) return 0;
    dest[i]=x;
  }
  if (i==dsize) return 0;
  dest[i]=0;
  return i+1;
}

static size_t utf16toutf8(char* dest,size_t dsize,uint16_t* src,size_t ssize) {
  size_t X,Y;
  char* x,* y;
  x=(char*)src;
  y=dest;
  X=ssize;
  Y=dsize?dsize-1:dsize;	// the -1 makes sure we have a 0 byte at the end
  memset(dest,0,dsize);
  if (iconv(wc2utf8,&x,&X,&y,&Y)) return 0;
  return dsize-Y;
}

static size_t utf8toutf16(char* dest,size_t dsize,const char* src) {
  /* src is a filename, so it might be either latin1 or utf8.
     try to parse it as utf8, but if we fail on a char, we assume it's latin1 */
  size_t c;
  char* orig=dest;
  while (*src) {
    if ((src[0]&0x80)==0) {
      c=src[0];
      ++src;
    } else if ((src[0]&0xe0)==0xc0 && (src[1]&0xc0)==0x80) {
      c=((src[0]&0x1f) << 6) + (src[1]&0x3f);
      src+=2;
    } else if ((src[0]&0xf0)==0xe0 && (src[1]&0xc0)==0x80 && (src[2]&0xc0)==0x80) {
      c=((src[0]&0xf) << 12) + ((src[1]&0x3f) << 6) + (src[2]&0x3f);
      src+=3;
    } else {
      /* we don't support longer UTF-8 sequences because you'd need more
       * than the 16 bits Windows has for them. */
      c=(unsigned char)src[0];
      ++src;
    }
    if (dsize<2) return 0;
    dest[0]=c&0xff;
    dest[1]=(c>>8);
    dest+=2;
    dsize-=2;
  }
  return dest-orig;
}


static int smb_open(struct http_data* h,unsigned short* remotefilename,size_t fnlen,struct stat* ss,enum smb_open_todo todo) {
  char localfilename[1024];
  int64 fd;
  size_t i,j;
  char* x;
  if (ip_vhost(h)==-1 || fnlen/2>sizeof(localfilename))
    return -1;

  fd=-1;
  for (j=0; fd==-1 && j<2; ++j) {
    if (j==0) {
      /* first try latin1 */
      if (utf16tolatin1(localfilename,sizeof(localfilename),remotefilename,fnlen)==0)
	continue;
    } else {
      if (utf16toutf8(localfilename,sizeof(localfilename),remotefilename,fnlen)==0)
	break;
    }
#if 0
    {
      const char* what[] = {"OPEN","STAT","CHDIR"};
      printf("trying \"%s\" for %s\n",localfilename,what[todo]);
    }
#endif
    for (i=0; localfilename[i]; ++i) {
      if (localfilename[i]=='\\')
	localfilename[i]='/';
    }
    x=(char*)localfilename;
    while ((x=strstr(x,"/.")))
      x[1]=':';
    x=(char*)localfilename;
    while (*x=='/') ++x;
    if (todo==WANT_STAT) {
      if (*x==0) x=".";
      if (stat(x,ss)==0) {
	fd=0;
	break;
      }
    } else if (todo==WANT_OPEN) {
      if (*x==0) x=".";
      if (open_for_reading(&fd,x,ss))
	break;
    } else if (todo==WANT_CHDIR) {
      if (!*x || chdir(x)==0) {
	fd=0;
	break;
      }
    }
  }

  return fd;
}

static int smb_handle_OpenAndX(struct http_data* h,unsigned char* c,size_t len,uint32_t pid,struct smb_response* sr) {
  static const char nr[34]=
    "\x0f"	// word count 15
    "\xff"	// AndXCommand
    "\x00"	// Reserved
    "w1"	// AndXOffset; ofs 3
    "w2"	// FID; ofs 5
    "\x00\x00"	// file attributes; normal file
    "u1__"	// ctime; ofs 9
    "u2__"	// file size; ofs 13
    "\x00\x00"	// granted access: read, compatibility mode, caching permitted
    "\x00\x00"	// file type: disk file or directory
    "\x00\x00"	// ipc state
    "\x01\x00"  // action: file existed and was opened
    "\x00\x00\x00\x00"	// server FID (?!?)
    "\x00\x00"	// reserved
    "\x00\x00"	// byte count 0
    ;
  if (len<2*15 || c[0]!=15) return -1;
  /* see if it is an open for reading */
  if ((c[7]&7) || ((c[17]&3)!=1)) {
    /* we only support read access */
//    printf("non-read-access requested: %x %x!\n",c[7],c[17]);
    set_smb_error(sr,ERROR_ACCESS_DENIED,0x2d);
    return 0;
  }
  /* now look at file name */
  {
    size_t fnlen=uint16_read((char*)c+31);
    uint16_t* remotefilename=(uint16_t*)(c+34);
    struct stat ss;
    struct handle* hdl;
    int fd;
    char* x;
    if (fnlen%2) --fnlen;
    if (fnlen>2046 || ((uintptr_t)remotefilename%2)) return -1;
    hdl=alloc_handle(&h->h);
    if (!hdl) {
//      printf("could not open file handle!");
      set_smb_error(sr,STATUS_TOO_MANY_OPENED_FILES,0x2d);
      return 0;
    }

    fd=smb_open(h,remotefilename,fnlen,&ss,WANT_OPEN);
    if (fd==-1) {
      set_smb_error(sr,ERROR_OBJECT_NAME_NOT_FOUND,0x2d);
      close_handle(hdl);
      return 0;
    }
    hdl->fd=fd;
    hdl->pid=pid;
    hdl->size=ss.st_size;
    hdl->cur=0;
    hdl->filename=malloc(fnlen+2);
    if (hdl->filename) {
      memcpy(hdl->filename+1,remotefilename,fnlen);
      hdl->filename[0]=fnlen;
    }

    {
      size_t oldlen=sr->used;
      if (!(x=add_smb_response2(sr,nr,15*2+3,0x2d))) return -1;
      uint16_pack(x+OFS16(nr,"w1"),oldlen+15*2+3);
    }

    uint16_pack(x+OFS16(nr,"w2"),hdl->handle);
    uint32_pack(x+OFS16(nr,"u1"),ss.st_mtime);
    uint32_pack(x+OFS16(nr,"u2"),ss.st_size);
  }
  return 0;
}

static int smb_handle_CreateAndX(struct http_data* h,const unsigned char* c,size_t len,uint32_t pid,struct smb_response* sr) {
  static const char template[]=
    "\x22"	// word count 34
    "\xff\x00"	// AndX: no further commands, reserved
    "w1"	// AndXOffset
    "\x00"	// No oplock granted
    "w2"	// FID
    "\x01\x00\x00\x00"	// Create Action: 1 == The file existed and was opened
    "q0______"	// ctime
    "q1______"	// atime
    "q2______"	// mtime
    "q3______"	// mtime
    "d1__"	// attributes; 0x10 == directory, 0x1 == read only
    "q4______"	// allocation size
    "q5______"	// end of file (0)
    "w3"	// file type (0 = file or directory)
    "w4"	// IPC state (lower 8 bits == link count?)
    "\x00"	// 0 = file, 1 = directory
    "\x00\x00";	// byte count 0

  if (len<2*24 || c[0]!=24) return -1;
  /* now look at file name */
  {
    size_t fnlen=uint16_read((char*)c+6);
    uint16_t* remotefilename=(uint16_t*)(c+0x34);
    struct stat ss;
    struct handle* hdl;
    int fd;
    // filename cannot be bigger than byte count says the total payload is
    if (uint16_read((char*)c+0x31)<fnlen) return -1;
    if (fnlen%2) --fnlen;
    if (fnlen>2046 || ((uintptr_t)remotefilename%2)) return -1;
    if (fnlen==14 && !memcmp(remotefilename,"\\\x00s\x00r\x00v\x00s\x00v\x00""c\x00",14)) {
      set_smb_error(sr,ERROR_OBJECT_NAME_NOT_FOUND,0xa2);
      return 0;
    }
    /* see if it is an open for reading */
    if ((c[16]&7)!=1) {
      /* we only support read access */
  //    printf("non-read-access requested: %x!\n",uint32_read(c+16));
      set_smb_error(sr,ERROR_ACCESS_DENIED,0xa2);
      return 0;
    }
    hdl=alloc_handle(&h->h);
    if (!hdl) {
//      printf("could not open file handle!");
      set_smb_error(sr,STATUS_TOO_MANY_OPENED_FILES,0xa2);
      return 0;
    }

    fd=smb_open(h,remotefilename,fnlen,&ss,WANT_OPEN);
    if (fd==-1) {
      set_smb_error(sr,ERROR_OBJECT_NAME_NOT_FOUND,0xa2);
      close_handle(hdl);
      return 0;
    }
    hdl->fd=fd;
    hdl->pid=pid;
    hdl->size=ss.st_size;
    hdl->cur=0;
    hdl->filename=malloc(fnlen+2);
    if (hdl->filename) {
      memcpy(hdl->filename+1,remotefilename,fnlen);
      hdl->filename[0]=fnlen;
    }

    {
      char* c=add_smb_response2(sr,template,1+2*34+2,0xa2);
      struct stat ss;
      if (!c) return -1;
      int isdir;
      fstat(hdl->fd,&ss);
      isdir=S_ISDIR(ss.st_mode);
      uint16_pack(c+OFS16(template,"w1"),sr->used);
      uint16_pack(c+OFS16(template,"w2"),hdl->handle);
      uint64_pack_ntdate(c+OFS16(template,"q0"),ss.st_ctime);
      uint64_pack_ntdate(c+OFS16(template,"q1"),ss.st_atime);
      uint64_pack_ntdate(c+OFS16(template,"q2"),ss.st_mtime);
      uint64_pack_ntdate(c+OFS16(template,"q3"),ss.st_mtime);
      uint32_pack(c+OFS16(template,"d1"),isdir?0x11:0x1);
      uint64_pack(c+OFS16(template,"q4"),0x100000);	// that's what Samba says
      uint64_pack(c+OFS16(template,"q5"),ss.st_size);	// end of file 
      uint16_pack(c+OFS16(template,"w3"),0);
      uint16_pack(c+OFS16(template,"w4"),ss.st_nlink>255?255:ss.st_nlink);
      if (isdir)
	c[OFS16(template,"w4")+2]=1;
    }
    return 0;
  }
}

static uint32_t mymax(uint32_t a,uint32_t b) {
  return a>b?a:b;
}

static int smb_handle_ReadAndX(struct http_data* h,unsigned char* c,size_t len,uint32_t pid,struct smb_response* sr) {
  static const char nr[]=
    "\x0c"	// word count 12
    "\xff"	// AndXCommand
    "\x00"	// Reserved
    "w0"	// AndXOffset; ofs 3
    "w1"	// Remaining; ofs 5
    "\x00\x00"	// data compaction mode
    "\x00\x00"	// reserved
    "w2"	// data length low; ofs 11
    "w3"	// data offset; ofs 13
    "\x00\x00\x00\x00"	// data length high (*64k)
    "\x00\x00\x00\x00\x00\x00"	// reserved
    "w4"	// byte count; ofs 24
    ;
  uint16_t handle;
  uint16_t count;
#if 0
  uint32_t relofs;
#endif
  struct handle* hdl;
  char* x;
  size_t oldused;
  if (len<2*10 || (c[0]!=10 && c[0]!=12)) return -1;

  handle=uint16_read((char*)c+5);
  if (!(hdl=deref_handle(&h->h,handle))) {
    set_smb_error(sr,STATUS_INVALID_HANDLE,0x2e);
    return 0;
  }

  hdl->cur=uint32_read((char*)c+7);
  if (c[0]==12)
    hdl->cur |= ((unsigned long long)uint32_read((char*)c+21))<<32;

#if 0
  relofs=uint32_read((char*)c+7);

  printf("cur %llu, size %llu, relofs %ld -> ",hdl->cur,hdl->size,relofs);
  if (relofs<0) {
    if (hdl->cur<-relofs) hdl->cur=0; else hdl->cur+=relofs;
  } else if (hdl->cur+relofs<hdl->size)
    hdl->cur+=relofs;
  else
    hdl->cur=hdl->size;

  printf("%llu\n",hdl->cur);
#endif

  if (uint32_read((char*)c+15))
    count=64000;
  else
    count=mymax(uint16_read((char*)c+13),uint16_read((char*)c+11));
  if (count>65500) count=65500;

#if 0
  printf("read: %i bytes from ofs %llu (file has %llu bytes)\n",count,hdl->cur,hdl->size);
#endif

  if (hdl->cur>hdl->size)
    count=0;
  else
    if (count>hdl->size-hdl->cur) count=hdl->size-hdl->cur;

  oldused=sr->used;
  if (!(x=add_smb_response2(sr,nr,12*2+3,0x2e))) {
    return -1;
  }
  uint16_pack(x+OFS16(nr,"w0"),0);	// no andx for read
  {
    off_t rem=hdl->size-hdl->cur-count;
    uint16_pack(x+OFS16(nr,"w1"),rem>0xffff?0xffff:rem);
  }
  uint16_pack(x+OFS16(nr,"w2"),count);
  uint16_pack(x+OFS16(nr,"w3"),oldused+12*2);
  uint16_pack(x+OFS16(nr,"w4"),count);

#ifdef DEBUG
  hexdump(sr->buf,sr->used);
#endif
  uint32_pack_big(sr->buf,sr->used-4+count);	// update netbios size field
  iob_addbuf_free(&h->iob,sr->buf,sr->used);
  iob_addfile(&h->iob,hdl->fd,hdl->cur,count);
  hdl->cur+=count;
  return 0;
}

static int smb_handle_Trans(unsigned char* c,size_t len,struct smb_response* sr) {
  /* windows 7 calls this when trying to copy a file via cmd.exe copy */
  /* samba replies STATUS_NOT_SUPPORTED.  works for me. */
#if 0
  if (len<0x34 || c[0]!=23) return -1;
  if (uint16_read(c+0x25)!=2) return -1;	/* not ioctl */
#endif
  /* we don't really care what ioctl they were trying to call */
  /* always return the same canned answer */
  set_smb_error(sr,ERROR_NOT_SUPPORTED,0xa0);
  return 0;
}

static int smb_handle_Trans2(struct http_data* h,unsigned char* c,size_t len,uint32_t pid,struct smb_response* sr) {
  uint16_t subcommand;
  uint16_t paramofs,paramcount;
  uint16_t dataofs;
  uint16_t loi=0;
  struct handle* hdl;
  struct stat ss;
  uint32_t attr;

  uint16_t* filename=0;
  uint16_t fnlen=0;

  if (len<2*15 || c[0]!=15) return -1;
  subcommand=uint16_read((char*)c+29);
  paramofs=uint16_read((char*)c+21);
  paramcount=uint16_read((char*)c+19);
  dataofs=uint16_read((char*)c+25);
  /* Do some general validation of the offsets and data counts */
  /* Accept crap in the offsets if the counts are zero */
  {
    size_t datacount=uint16_read((char*)c+23);
    if ((paramcount && !range_bufinbuf(c+c[0]*2,len-c[0]*2,c-smbheadersize+paramofs,paramcount)) ||
	(datacount && !range_bufinbuf(c+c[0]*2,len-c[0]*2,c-smbheadersize+dataofs,datacount)))
      return -1;
    if (dataofs > len+smbheadersize) return -1;
    if (datacount && paramofs+paramcount > dataofs) return -1;
  }
  if (subcommand==7 ||	// QUERY_FILE_INFO
      subcommand==5 ||	// QUERY_PATH_INFO
      subcommand==3) {	// QUERY_FS_INFO
    if (subcommand==7) {
      // QUERY_FILE_INFO
      if (paramcount<4) return -1;
      if (!(hdl=deref_handle(&h->h,uint16_read((char*)c-smbheadersize+paramofs)))) {
	set_smb_error(sr,STATUS_INVALID_HANDLE,0x32);
	return 0;
      }
      if (fstat(hdl->fd,&ss)==-1)
	goto filenotfound;
      if (hdl->filename) {
	fnlen=hdl->filename[0];
	filename=hdl->filename+1;
	if (fnlen && filename[fnlen-1]==0 && filename[fnlen-2]==0) fnlen-=2;
      }
      loi=uint16_read((char*)c-smbheadersize+paramofs+2);
    } else if (subcommand==5) {
      // QUERY_PATH_INFO
      filename=(uint16_t*)(c-smbheadersize+paramofs+6);
      if ((uintptr_t)filename % 2)
	goto filenotfound;
      if (paramcount<8) return -1;
      fnlen=paramcount-6;
      if (smb_open(h,filename,fnlen,&ss,WANT_STAT)==-1)
	goto filenotfound;
      loi=uint16_read((char*)c-smbheadersize+paramofs);
    } else if (subcommand==3) {
      // QUERY_FS_INFO
      loi=uint16_read((char*)c-smbheadersize+paramofs);
      if (loi==0x102)
	return add_smb_response(sr,
	  "\x0a\x00\x00\x18\x00\x00\x00\x00\x00\x38"
	  "\x00\x00\x00\x18\x00\x38\x00\x00\x00\x00"
	  "\x00\x19\x00\x00\x00\x00\x00\x00\x00\x00"
	  "\x00\x00\xde\xc0\xfe\xfe\x06\x00\x00\x00"
	  "\x00\x00\x66\x00\x74\x00\x70\x00",48,0x32);
      else if (loi==0x103) {
	/* UINT64 TotalAllocationUnits
	 * UINT64 AvailableAllocationUnits
	 * UINT32 SectorsPerAllocationUnit
	 * UINT32 BytesPerSector */
	static const char tmpl[]=
	  "\x0a\x00\x00\x18\x00\x00\x00\x00\x00\x38"
	  "\x00\x00\x00\x18\x00\x38\x00\x00\x00\x00"
	  "\x00\x19\x00";
	size_t len=sizeof(tmpl)+8+8+4+4;
	char* buf=alloca(len);
	char* x=buf+sizeof(tmpl);
	struct statvfs sv;
	memcpy(buf,tmpl,sizeof(tmpl));
	if (fstatvfs(origdir,&sv)==-1) {
	  set_smb_error(sr,ERROR_OBJECT_NAME_NOT_FOUND,0x32);
	  return 0;
	}
	uint64_pack(x,sv.f_blocks);
	uint64_pack(x+8,sv.f_bavail);
	uint32_pack(x+8+8,sv.f_frsize);
	uint32_pack(x+8+8+4,512);
	return add_smb_response(sr,buf,len,0x32);
      } else if (loi==0x105)
	return add_smb_response(sr,
	  "\x0a\x00\x00\x12\x00\x00\x00\x00\x00\x38"
	  "\x00\x00\x00\x12\x00\x38\x00\x00\x00\x00"
	  "\x00\x13\x00\x00\x46\x00\x08\x00\xff\x00"
	  "\x00\x00\x08\x00\x00\x00p\x00u\x00"
	  "b\x00\x00\x00",43,0x32);
      else goto filenotfound;
    } else {
filenotfound:
      set_smb_error(sr,ERROR_OBJECT_NAME_NOT_FOUND,0x32);
      return 0;
    }
    if (S_ISDIR(ss.st_mode))
      attr=0x10;	// directory
    else
      attr=0x80;	// plain file
    switch (loi) {
    case 0x101:		// SMB_QUERY_FILE_BASIC
    case 0x102:		// SMB_QUERY_FILE_STANDARD
    case 0x103:		// Query File EA Info
      {
	char* buf;
	size_t datacount=(loi==0x101?4*8+4:2*8+4+2);	// 4x8 for dates, 4 for file attributes, 4 extra
	if (loi==0x103) datacount=4;
	buf=alloca(20+100+datacount);
	byte_copy(buf,21,
	  "\x0a"		// word count
	  "\x02\x00"	// total parameter count
	  "xx"		// total data count; ofs 3
	  "\x00\x00"	// reserved
	  "\x02\x00"	// parameter count
	  "xx"		// parameter offset; ofs 9
	  "\x00\x00"	// parameter displacement
	  "xx"		// data count (same as total data count); ofs 13
	  "xx"		// data offset; ofs 15
	  "\x00\x00"	// data displacement
	  "\x00"		// setup count
	  "\x00");	// reserved
	uint16_pack(buf+3,datacount);
	uint16_pack(buf+9,sr->used-4+24);
	uint16_pack(buf+13,datacount);
	uint16_pack(buf+15,sr->used+24);
	uint16_pack(buf+21,datacount);
	buf[23]=0;
	uint16_pack(buf+24,0);	// ea error offset
	uint16_pack(buf+26,0);	// padding
	if (loi==0x101) {
	  uint64_pack_ntdate(buf+28,ss.st_ctime);
	  uint64_pack_ntdate(buf+28+8,ss.st_atime);
	  uint64_pack_ntdate(buf+28+8+8,ss.st_mtime);
	  uint64_pack_ntdate(buf+28+8+8+8,ss.st_mtime);
	  uint32_pack(buf+60,attr);	// normal file
	  uint32_pack(buf+64,0);
	} else if (loi==0x102) {
	  uint16_pack(buf+21,datacount+5);
	  uint64_pack(buf+28,(unsigned long long)ss.st_blocks*512);
	  uint64_pack(buf+28+8,ss.st_size);
	  uint32_pack(buf+28+8+8,ss.st_nlink);
	  buf[28+8+8+4]=0;
	  buf[28+8+8+4+1]=S_ISDIR(ss.st_mode)?1:0;
	} else if (loi==0x103) {
	  uint32_pack(buf+28,0);	// EA List Length 0
	}
	return add_smb_response(sr,buf,60+datacount,0x32);
      }
    case 0x0107:	// SMB_QUERY_FILE_ALL_INFO
      {
	char* buf;
	size_t datacount=72+fnlen;
	buf=alloca(20+100+datacount);
	byte_copy(buf,21,
	  "\x0a"		// word count
	  "\x02\x00"	// total parameter count
	  "xx"		// total data count; ofs 3
	  "\x00\x00"	// reserved
	  "\x02\x00"	// parameter count
	  "xx"		// parameter offset; ofs 9
	  "\x00\x00"	// parameter displacement
	  "xx"		// data count (same as total data count); ofs 13
	  "xx"		// data offset; ofs 15
	  "\x00\x00"	// data displacement
	  "\x00"		// setup count
	  "\x00");	// reserved
	uint16_pack(buf+3,datacount);
	uint16_pack(buf+9,sr->used-4+24);
	uint16_pack(buf+13,datacount);
	uint16_pack(buf+15,sr->used+24);
	uint16_pack(buf+21,datacount);
	buf[23]=0;
	uint16_pack(buf+24,0);	// ea error offset
	uint16_pack(buf+26,0);	// padding
	uint64_pack_ntdate(buf+28,ss.st_ctime);
	uint64_pack_ntdate(buf+28+8,ss.st_atime);
	uint64_pack_ntdate(buf+28+8+8,ss.st_mtime);
	uint64_pack_ntdate(buf+28+8+8+8,ss.st_mtime);
	uint32_pack(buf+60,attr);	// normal file
	uint64_pack(buf+68,(unsigned long long)ss.st_blocks*512);
	uint64_pack(buf+76,ss.st_size);
	uint32_pack(buf+84,ss.st_nlink);
	byte_zero(buf+88,8);
	uint32_pack(buf+96,fnlen);
	if (fnlen)
	  byte_copy(buf+100,fnlen,filename);
	return add_smb_response(sr,buf,28+datacount,0x32);
      }
    default:
      set_smb_error(sr,ERROR_ACCESS_DENIED,0x32);
      return 0;
    }
  } else if (subcommand==1 ||	// FIND_FIRST2
	     subcommand==2) {	// FIND_NEXT2
    size_t i,l,rl=0;
    size_t maxdatacount,sizeperrecord=0;
    char* globlatin1,* globutf8;
    uint16_t attr;
    uint16_t* resume;
    DIR* d;
#if 0
    if (subcommand==1)
      printf("Incoming FIND_FIRST2!\n");
    else
      printf("Incoming FIND_NEXT2!\n");
#endif
    if (sr->used>16*1024) {
outofmemory:
      set_smb_error(sr,ERROR_NO_MEMORY,0x32);
      return 0;
    }
    if (paramcount<18)
      return -1;		// need at least six chars for "/*" in unicode
    maxdatacount=uint16_read((char*)c+7);
    attr=uint16_read((char*)c-smbheadersize+paramofs);
    if (subcommand==1)
      loi=uint16_read((char*)c-smbheadersize+paramofs+6);
    else
      loi=uint16_read((char*)c-smbheadersize+paramofs+4);
    if (loi!=0x104 && loi!=0x102) {
      set_smb_error(sr,ERROR_NOT_SUPPORTED,0x32);
      return 0;
    }
    if (loi==0x104)
      sizeperrecord=0x5e;
    else if (loi==0x102)
      sizeperrecord=0x44;
    if (subcommand==1) {
      h->smbattrs=attr;
      filename=(uint16*)(c-smbheadersize+paramofs+12);
      l=(paramcount-12)/2;
      if ((h->ftppath=malloc(l+l+4))) {
	memcpy(h->ftppath+2,filename,l+l+2);
	((uint16*)h->ftppath)[0]=l;
#if 0
	{
	  size_t i;
	  printf("storing ftppath \"");
	  for (i=0; i<l; ++i)
	    printf("%c",h->ftppath[i]);
	  printf("\"\n");
	}
#endif
      }
      resume=0;
    } else {
      attr=h->smbattrs;
      resume=(uint16*)(c-smbheadersize+paramofs+12);
      rl=paramcount-12;

      /* validate the resume filename */
      if ((uintptr_t)resume % 2)
	goto filenotfound;
      if (resume[rl-1])
	goto filenotfound;		// want null terminated filename
      for (i=0; i<rl; ++i)
	if (uint16_read((char*)&resume[i])=='\\' || uint16_read((char*)&resume[i])=='/') {
//	  printf("resume filename contains %c!\n",resume[i]);
	  goto filenotfound;	// resume filename cannot contain \ or /
	}

      if (!h->ftppath) {
//	printf("h->ftppath is NULL!\n");
	goto filenotfound;
      }
      filename=(uint16*)(h->ftppath);
      l=filename[0];
#if 0
      {
	size_t i;
	printf("retrieved ftppath \"");
	for (i=0; i<l; ++i)
	  printf("%c",filename[i]);
	printf("\", resume at \"");
	for (i=0; i<rl; ++i)
	  printf("%c",resume[i]);
	printf("\"\n");
      }
#endif

      ++filename;
    }

    {
      /* we want to minimize copies, so we realloc enough space into the
       * smb buffer right from the start. */
      char* tmp=realloc(sr->buf,sr->used+maxdatacount+100);
      if (!tmp) goto outofmemory;
      sr->buf=tmp;
    }
    sr->allocated=sr->used+maxdatacount+100;

    if ((uintptr_t)filename % 2)
      goto filenotfound;
    if (l==0 || filename[l-1])
      return -1;		// want null terminated filename
    if (uint16_read((char*)&filename[l-1])=='\\' || uint16_read((char*)&filename[l-1])=='/')
      goto filenotfound;	// can't glob if filename ends in \ or /
    if (uint16_read((char*)&(filename[0]))!='\\')
      goto filenotfound;
    for (i=0; i+2<l; ++i)
      if (uint16_read((char*)&filename[i])<0x1f) {
	set_smb_error(sr,STATUS_OBJECT_NAME_INVALID,0x32);
	return 0;
      }
    for (i=l; i>0; --i)
      if (uint16_read((char*)&filename[i])=='\\') {
	filename[i]=0;
	break;
      }
    fnlen=i*2;
    if (smb_open(h,filename+1,fnlen,0,WANT_CHDIR)==-1)
      goto filenotfound;
    filename+=i+1; l-=i;
    globlatin1=alloca(l+1);

#if 0
    {
      int j;
      printf("convert \"");
      for (j=0; filename[j]; ++j)
	printf("%c",filename[j]);
      printf("\" (source size: %d, dest size %d)\n",(l+1)*2,l+1);
    }
#endif

    if (utf16tolatin1(globlatin1,l+1,filename,(l+1)*2)) {
      globlatin1=0;
//      puts("could not convert glob expression to latin1!");
    } // else
//      printf("glob expression \"%s\"\n",globlatin1);
    globutf8=alloca((l+1)*3);
    if (utf16toutf8(globutf8,(l+1)*3,filename,(l+1)*3)) {
      globutf8=0;
 //     puts("could not convert glob expression to utf-8!");
    }
    if (globlatin1 && globutf8 && !strcmp(globutf8,globlatin1)) globutf8=0;
    if (!globlatin1 && !globutf8)
      goto filenotfound;

    d=opendir(".");
    if (d) {
      struct dirent* de;
      struct stat ss;
      size_t actualnamelen;
      size_t searchcount=0;
      char* cur=0,* max=0,* base=0,* trans2=0,* smbhdr,* last=0;
      smbhdr=sr->buf+4;

      while ((de=readdir(d))) {

#ifdef DT_DIR
	if (de->d_type!=DT_DIR && de->d_type!=DT_REG && de->d_type!=DT_LNK) continue;
	if (de->d_type==DT_DIR && !(attr&0x10)) continue;
#else
	if (lstat(de->d_name,&ss)) continue;
	if (!S_ISDIR(ss.st_mode) && !S_ISREG(ss.st_mode) && !S_ISLNK(ss.st_mode)) continue;
	if (S_ISDIR(ss.st_mode) && !(attr&0x10)) continue;
#endif

	if (de->d_name[0]=='.') continue;
	if (de->d_name[0]==':') de->d_name[0]='.';
//	if (globlatin1)
//	  printf("matching %s vs %s\n",globlatin1,de->d_name);
//	if (globutf8)
//	  printf("matching %s vs %s\n",globutf8,de->d_name);
	if ((globlatin1 && globmatch(globlatin1,de->d_name)) ||
	    (globutf8 && globmatch(globutf8,de->d_name))) {
#ifndef DT_DIR
	  if (S_ISLNK(ss.st_mode))
#endif
	  if (stat(de->d_name,&ss)==-1) continue;
//	  printf("globbed ok: %s\n",de->d_name);
	  if (!base) {
	    trans2=sr->buf+sr->used;
	    add_smb_response(sr,
		"\x0a"		// word count
		"\x0a\x00"	// total param count
		"xx"		// total data count; ofs 3
		"\x00\x00"	// reserved
		"\x0a\x00"	// param count
		"xx"		// param ofs; ofs 9
		"\x00\x00"	// param displacement (?!)
		"xx"		// data count; ofs 13
		"xx"		// data offset; ofs 15
		"\x00\x00"	// data displacement
		"\x00"		// setup count
		"\x00"		// reserved
		"xx"		// byte count; ofs 21
		"\x00"		// padding
		// FIND_FIRST2 Parameters
		"\x01\x00"	// search id 1
		"\x01\x00"	// search count (?!?); ofs 26
		"\x01\x00"	// end of search; ofs 28
		"\x00\x00"	// ea error offset
		"xx"		// last name offset; ofs 32
		"\x00\x00"	// padding
		// FIND_FIRST2 Data
		,36,0x32);
	    if (subcommand==2) {
	      trans2[1]=8;	// total param count
	      trans2[7]=8;	// param count
	      memcpy(trans2+24,
		  // FIND_NEXT2 Parameters
		  "\x01\x00"	// search count (?!?); ofs 24
		  "\x01\x00"	// end of search; ofs 26
		  "\x00\x00"	// ea error offset
		  "xx"		// last name offset; ofs 30
		  // FIND_NEXT2 Data
		  ,8);
	      sr->used-=4;
	    }

	    cur=base=sr->buf+sr->used;
	    max=sr->buf+sr->allocated;
	  }
	  if (max-cur < 100+0x60 +strlen(de->d_name)*2 ||
	      !(actualnamelen=utf8toutf16(cur+sizeperrecord,max-cur-sizeperrecord,de->d_name))) {
	    // not enough space!  abort!  abort!
	    if (subcommand==1)
	      trans2[28]=0;
	    else
	      trans2[26]=0;
//	    printf("not enough space!\n");
	    break;
	  }

	  /* if this is a FIND_NEXT and we have not reached the resume
	   * filename yet, resume is not NULL. */
	  if (resume) {
#if 0
	    printf("actualnamelen=%u rl=%u cur+sizeperrecord=\"",actualnamelen,rl);
	    {
	      size_t i;
	      char a[6];
	      uint32_t ch;
	      for (i=0; i<actualnamelen; i+=2) {
		ch=uint16_read(cur+sizeperrecord+i);
		a[fmt_utf8(a,ch)]=0;
		printf("%s",a);
	      }
	      printf("\" resume=\"");
	      for (i=0; i<rl; i++) {
		ch=uint16_read((char*)(resume+i));
		a[fmt_utf8(a,ch)]=0;
		printf("%s",a);
	      }
	      printf("\"\n");
	    }
#endif
	    if (actualnamelen+2==rl && byte_equal(cur+sizeperrecord,actualnamelen,resume))
	      resume=0;
	    continue;
	  }

	  last=cur;
	  if (loi==0x104 || loi==0x102) {
	    size_t padlen=sizeperrecord +actualnamelen;
	    if (padlen%4) padlen+=2;
	    uint32_pack(cur,padlen);
	    cur+=4;
	    uint32_pack(cur,0); cur+=4;	// "file index", samba sets this to 0
	    uint64_pack_ntdate(cur,ss.st_ctime); cur+=8;
	    uint64_pack_ntdate(cur,ss.st_atime); cur+=8;
	    uint64_pack_ntdate(cur,ss.st_mtime); cur+=8;
	    uint64_pack_ntdate(cur,ss.st_mtime); cur+=8;
	    uint64_pack(cur,ss.st_size); cur+=8;
	    uint64_pack(cur,512*ss.st_blocks); cur+=8;
	    uint32_pack(cur,S_ISDIR(ss.st_mode)?0x10:0x80); cur+=4;
	    uint32_pack(cur,actualnamelen); cur+=4;
	    uint32_pack(cur,0); cur+=4;	// ea list length
	    if (loi==0x104) {
	      cur[0]=0;	// short file name len
	      cur[1]=0;	// reserved
	      cur+=2;
	      byte_zero(cur,24);	// the short name
	      cur+=24+actualnamelen;
	    } else {
	      cur+=actualnamelen;
	    }
	    if ((uintptr_t)cur%4) cur+=2;
	    ++searchcount;
	    sr->used=cur-sr->buf;
	    assert(sr->used<sr->allocated);
	  }
	}
      }
      closedir(d);
      filename[-1]='\\';
      if (!searchcount) {
	if (subcommand==1) goto filenotfound;
      }
      if (trans2) {
	uint16_pack(trans2+3,cur-base);
	uint16_pack(trans2+9,trans2+20-sr->buf);
	uint16_pack(trans2+13,cur-base);
	uint16_pack(trans2+15,base-smbhdr);
	if (subcommand==1) {
	  uint16_pack(trans2+21,cur-base+13);
	  uint16_pack(trans2+26,searchcount);	// search count...!?
	  uint16_pack(trans2+32,last-base);
	} else {
	  uint16_pack(trans2+21,cur-base+11);
	  uint16_pack(trans2+24,searchcount);	// search count...!?
	  uint16_pack(trans2+30,last-base);
	}
      }
      uint32_pack_big(sr->buf,sr->used-4);
//      printf("sr->used = %u\n",sr->used);
      return 0;
    }
    goto filenotfound;

  } else
    return -1;
}

static int smb_handle_close2(unsigned char* c,size_t len,struct smb_response* sr) {
  return add_smb_response(sr,"\x00\x00\x00",3,0x52);
}

static int smb_handle_Close(struct http_data* h,unsigned char* c,size_t len,struct smb_response* sr) {
  struct handle* hdl;
  if (len<2*3 || c[0]!=3) return -1;
  if (!(hdl=deref_handle(&h->h,uint16_read((char*)c+1)))) {
    set_smb_error(sr,STATUS_INVALID_HANDLE,0x4);
    return 0;
  }
  close_handle(hdl);
  return add_smb_response(sr,"\x00\x00\x00",3,0x4);
}

static void fmt_dostime(char* d,time_t t) {
  struct tm lt;
  localtime_r(&t,&lt);
  /* date + time as 16-bit values */
  uint16_pack(d,lt.tm_mday + ((lt.tm_mon+1)<<5) + ((lt.tm_year-80)<<9));
  uint16_pack(d+2,(lt.tm_sec/2) + (lt.tm_min<<5) + (lt.tm_hour<<11));
}

static int smb_handle_Query_Information2(struct http_data* h,unsigned char* c,size_t len,struct smb_response* sr) {
  struct handle* hdl;
  struct stat ss;
  char buf[100];
  if (len<2 || c[0]!=1) return -1;
  if (!(hdl=deref_handle(&h->h,uint16_read((char*)c+1)))) {
    set_smb_error(sr,STATUS_INVALID_HANDLE,0x23);
    return 0;
  }
  if (fstat(hdl->fd,&ss)==-1) {
    /* can't happen */
    set_smb_error(sr,ERROR_OBJECT_NAME_NOT_FOUND,0x23);
    return 0;
  }
  buf[0]=12;	/* word count */
  /* ctime, atime, mtime, size, allocation size, attributes (2), byte count */
  fmt_dostime(buf+1,ss.st_ctime);
  fmt_dostime(buf+1+4,ss.st_atime);
  fmt_dostime(buf+1+4+4,ss.st_mtime);
  uint32_pack(buf+1+4+4+4,ss.st_size);
  uint32_pack(buf+1+4+4+4+4,ss.st_blocks*512);
  buf[1+4+4+4+4+4]=1+(S_ISDIR(ss.st_mode)?0x10:0);	/* the 1 is for read-only */
  buf[1+4+4+4+4+4+1]=0;
  buf[1+4+4+4+4+4+2]=0;
  buf[1+4+4+4+4+4+3]=0;
  return add_smb_response(sr,buf,1+4+4+4+4+4+5,0x23);
}

static int smb_handle_QueryDiskInfo(unsigned char* c,size_t len,struct smb_response* sr) {
  struct statvfs sv;
  char buf[13];
  unsigned long long l,k;
  size_t i;
  if (len<3 || c[0]!=0) return -1;
  if (fstatvfs(origdir,&sv)==-1) {
    set_smb_error(sr,ERROR_ACCESS_DENIED,0x80);
    return 0;
  }
  l=(unsigned long long)sv.f_blocks*sv.f_bsize;
  k=(unsigned long long)sv.f_bavail*sv.f_bsize;
  for (i=0; l>0xffff; ++i) l>>=1;

  buf[0]=5;
  /* ok, this protocol sucks royally; it works in clusters, and you can
   * only express total and free space in clusters, AND you only have 16
   * bits. */
  if (i>30) {
    i=30;
    uint16_pack(buf+1,0xffff);
    if ((k>>i)>0xffff)
      uint16_pack(buf+7,0xffff);
    else
      uint16_pack(buf+7,k>>i);
  } else {
    uint16_pack(buf+1,l);
    uint16_pack(buf+7,k>>i);
    if (i<9+15) {
      uint16_pack(buf+5,1<<9);
      uint16_pack(buf+3,(i<9)?1:(1<<(i-9)));
    } else {
      uint16_pack(buf+5,1<<15);
      uint16_pack(buf+3,1<<(i-15));
    }
  }
  uint32_pack(buf+9,0);
  return add_smb_response(sr,buf,13,0x80);
}

int smbresponse(struct http_data* h,int64 s) {
  unsigned char* c=array_start(&h->r);
  unsigned char* smbheader;
  size_t len,cur;
  struct smb_response sr;
  unsigned char andxtype;

  ++rps1;
  h->keepalive=0;
  /* is it SMB? */
  if ((size_t)array_bytes(&h->r)<4+smbheadersize)
    /* uh, what does an error look like? */
    /* dunno, samba doesn't say anything, it just ignores the packet. */
    /* if it's good enough for samba, it's good enough for me. */
    return 0;
  len=uint32_read_big((char*)c)&0xffffff;
  if (len<smbheadersize) {
//    printf("netbios len (%u) < smbheadersize (%u)\n",len,smbheadersize);
    return 0;
  }

//  hexdump(c,len+netbiosheadersize);

  if (validate_smb_packet(c+netbiosheadersize,len)==-1) {
//    printf("invalid smb packet!\n");
//    hexdump(c,len+netbiosheadersize);
//    validate_smb_packet(c+netbiosheadersize,len);
    return -1;
  }

  /* is it a request?  Discard replies. */
  if (c[13]&0x80) return 0;

  init_smb_response(&sr,c+netbiosheadersize,len);

  c+=netbiosheadersize;
  smbheader=c;

  /* loop over AndX crap */
  andxtype=c[4];
  for (cur=smbheadersize; cur<len && andxtype!=0xff; ) {

    /* what kind of request is it? */
    switch (andxtype) {
    case 0x04:
      /* Close Request */
      if (smb_handle_Close(h,c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;

    case 0x10:
      /* Check Directory Request */
      break;

    case 0x23:
      /* Query Information2 */
      if (smb_handle_Query_Information2(h,c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;

    case 0x2b:
      if (smb_handle_echo(c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;

    case 0x2d:
      /* Open AndX Request */
      if (smb_handle_OpenAndX(h,c+cur,len-cur,uint16_read((char*)smbheader+0x1a),&sr)==-1)
	goto kaputt;
      break;

    case 0x2e:
      /* Read AndX Request */
      if (smb_handle_ReadAndX(h,c+cur,len-cur,uint16_read((char*)smbheader+0x1a),&sr)==-1)
	goto kaputt;
      goto added;

    case 0x32:
      /* Trans2 Request; hopefully QUERY_FILE_INFO */
      if (smb_handle_Trans2(h,c+cur,len-cur,uint16_read((char*)smbheader+0x1a),&sr)==-1)
	goto kaputt;
      break;

    case 0x52:
      /* Find Close2 */
      if (smb_handle_close2(c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;

    case 0x71:
      /* Tree Disconnect Request */
      if (smb_handle_TreeDisconnect(c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;

    case 0x72:
      /* protocol negotiation request */
      if (smb_handle_negotiate_request(c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;

    case 0x73:
      /* Session Setup AndX Request */
      if (smb_handle_SessionSetupAndX(c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;


    case 0x75:
      /* Tree Connect AndX Request */
      if (smb_handle_TreeConnectAndX(c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;

    case 0x80:
      if (smb_handle_QueryDiskInfo(c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;

    case 0xa0:
      if (smb_handle_Trans(c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;

    case 0xa2:
      if (smb_handle_CreateAndX(h,c+cur,len-cur,uint16_read((char*)smbheader+0x1a),&sr)==-1)
	goto kaputt;
      break;

    default:
      set_smb_error(&sr,ERROR_NOT_SUPPORTED,andxtype);
    }
    if (!hasandx(andxtype)) break;
    andxtype=c[cur+1];
    if (andxtype==0xff) break;
    if (cur+5>len)
      goto kaputt;
    else {
      size_t next=uint16_read((char*)smbheader+cur+3);
      if (next<=cur || next>len)
	goto kaputt;
      cur=next;
    }
  }

#ifdef DEBUG
  hexdump(sr.buf,sr.used);
#endif

  iob_addbuf_free(&h->iob,sr.buf,sr.used);
added:
  io_dontwantread(s);
  io_wantwrite(s);
  h->keepalive=1;
  return 0;
kaputt:
  free(sr.buf);
  return -1;
}

#endif /* SUPPORT_SMB */


