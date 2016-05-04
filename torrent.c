#include <stddef.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <str.h>
#include <textcode.h>
#include "havealloca.h"

size_t fmt_benc_string(char* dest,const char* string,size_t len) {
  size_t i;
  i=fmt_ulong(dest,len);
  if (dest) {
    dest[i]=':';
    memcpy(dest+i+1,string,len);
  }
  return len+i+1;
}

size_t fmt_benc_int(char* dest,long long int number) {
  size_t i;
  if (!dest) return fmt_long(0,number)+2;
  dest[0]='i';
  i=fmt_long(dest+1,number);
  dest[i+1]='e';
  return i+2;
}

size_t fmt_benc_list(char* dest,const char* buf,size_t len) {
  size_t i;
  if (!dest) return len+2;
  dest[i]='l';
  memcpy(dest+1,buf,len);
  dest[i+1]='e';
}

size_t fmt_benc_dict(char* dest,const char* buf,size_t len) {
  size_t i;
  if (!dest) return len+2;
  dest[i]='d';
  memcpy(dest+1,buf,len);
  dest[i+1]='e';
}

size_t scan_benc_int(const char* src,unsigned long long* l) {
  if (*src=='i') {
    size_t i=scan_ulonglong(src+1,l);
    if (src[i+1]=='e')
      return i+2;
  }
  return 0;
}

size_t scan_benc_string(const char* src,char** c,size_t* len) {
  unsigned long l;
  size_t i=scan_ulong(src,&l);
  if (i && src[i]==':') {
    *c=(char*)src+i+1;
    *len=l;
    return l+i+1;
  }
  return 0;
}

// http://tracker.bla.org/announce?info_hash=%c3%f4%31%0e%aa%ec%ae%3d%84%c1%63%70%a2%36%67%6b%24%99%b6%e1&peer_id=-TR0006-u0u5j57kcmm4&port=6887&uploaded=0&downloaded=0&left=243269632&compact=1&numwant=50&key=njyytouhv5fymdafkhzi&event=started

/* http://wiki.theory.org/BitTorrentSpecification#Tracker_HTTP.2FHTTPS_Protocol */
/* http://www.bittorrent.org/protocol.html */

struct peer_state {
  struct peer_state* next;
  char peer_id[40];
  char key[32];
  char ip[16];
  unsigned short port;
  unsigned long long uploaded, downloaded, left;
  enum { STARTED, STOPPED, COMPLETED } state;
};

struct torrent_state {
  struct torrent_state* next;
  struct peer_state* peers;
  char info_hash[20];
};

struct torrent_state* root;

int parse_url(const char* c) {
  char* x=strchr(c,'\n');
  char* s;
  char infohash[60];
  size_t destlen;
  struct peer_state ps;
  int i,ok=0,compact=0;
  unsigned long numwant;
  char key[128/8];
  if (!x) return -1;
  if (x[-1]=='\r') --x;
  s=alloca(x-c+1);
  memcpy(s,c,x-c);
  s[x-c]=0;
  c=strchr(s,'?');
  if (!c) return -1;
  ++c;
  do {
    x=strchr(c,'&');
    if (x)
      *x++=0;
    else
      x=strchr(c,'\0');
    if (str_start(c,"info_hash=")) {
      c+=10;
      if (x-c>61) return -1;
      i=scan_urlencoded2(c,infohash,&destlen);
      if (c[i] || destlen!=20) return -1;
      byte_zero(&ps,sizeof(ps));
      ok=1;
    } else if (str_start(c,"peer_id=")) {
      c+=8;
      if (x-c>sizeof(ps.peer_id)) return -1;
      i=scan_urlencoded2(c,ps.peer_id,&destlen);
      if (c[i]) return -1;
      ps.peer_id[destlen]=0;
    } else if (str_start(c,"port=")) {
      c+=5;
      i=scan_ushort(c,&ps.port);
      if (c[i] || !port) return -1;
    } else if (str_start(c,"uploaded=")) {
      c+=9;
      i=scan_ulonglong(c,&ps.uploaded);
      if (c[i]) return -1;
    } else if (str_start(c,"downloaded=")) {
      c+=11;
      i=scan_ulonglong(c,&ps.downloaded);
      if (c[i]) return -1;
    } else if (str_start(c,"left=")) {
      c+=5;
      i=scan_ulonglong(c,&ps.left);
      if (c[i]) return -1;
    } else if (str_equal(c,"compact=1")) {
      compact=1;
    } else if (str_start(c,"numwant=")) {
      c+=8;
      i=scan_ulonglong(c,&numwant);
      if (c[i]) return -1;
      if (numwant>50) numwant=50;
    } else if (str_start(c,"key=")) {
      c+=4;
      if (strlen(c)!=128/8*2) return -1;
      i=scan_hexdump(c,key);
      if (c[i]) return -1;
    }

// http://tracker.bla.org/announce?info_hash=%c3%f4%31%0e%aa%ec%ae%3d%84%c1%63%70%a2%36%67%6b%24%99%b6%e1&peer_id=-TR0006-u0u5j57kcmm4&port=6887&uploaded=0&downloaded=0&left=243269632&compact=1&numwant=50&key=njyytouhv5fymdafkhzi&event=started
    c=x;
  } while (c);
}

int main() {
  char buf[100];
  int i;
  unsigned long long ull;
  char* c;
  size_t l;
#if 0
  buf[i=fmt_benc_string(buf,"fnord",5)]=0; puts(buf);
  buf[i]='x';
  printf("%d %d\n",i,scan_benc_string(buf,&c,&l));
  buf[i=fmt_benc_int(buf,1234)]=0; puts(buf);
  buf[i]='x';
  printf("%d %d\n",i,scan_benc_int(buf,&ull));
#endif
  c="GET /announce?info_hash=%c3%f4%31%0e%aa%ec%ae%3d%84%c1%63%70%a2%36%67%6b%24%99%b6%e1&peer_id=-TR0006-u0u5j57kcmm4&port=6887&uploaded=0&downloaded=0&left=243269632&compact=1&numwant=50&key=njyytouhv5fymdafkhzi&event=started\r\n\r\n";
  l=strlen(c);
  parse_url(c);
}
