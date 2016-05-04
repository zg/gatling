/*
  pass the name of a rules files as argv[1]
  then pipe in the gatling log file processed by acc on stdin
  on stdout you'll get those lines annotated by the network name that matched a rule
  rules look like this:

inetnum:      10.0.0.0 - 10.255.255.255
netname:      reserved 10.* range

  This format is the convention of the RIPE whois records for IP objects
*/
#include <string.h>
#include <buffer.h>
#include <scan.h>
#include <unistd.h>
#include <errmsg.h>
#include <str.h>
#include <fmt.h>
#include <ctype.h>
#include <ip6.h>

char _buf[8192];

struct net {
  char first[16],last[16];
  char* name;
  struct net* next;
}* root,** next=&root,* cur;

int main(int argc,char* argv[]) {
  buffer b;
  char line[2048];
  int r,whined;
  size_t lineno=0;
  if (!argv[1])
    die(0,"usage: ",argv[0]," ip-ranges.txt");
  if (buffer_mmapread(&b,argv[1]))
    diesys(1,"open");
  while ((r=buffer_getline(&b,line,sizeof line))>=0) {
    char linenoasc[10];
    char* c;
    ++lineno;
    linenoasc[fmt_ulong(linenoasc,lineno)]=0;
    if (r==0 && line[r]!='\n') break;
    line[r]=0;
    if (str_start(line,"inetnum:")) {
      c=line+8;
parseiprange:
      for (; *c==' ' || *c=='\t'; ++c) ;
      if (isxdigit(*c)) {
	char* d=strstr(c," - ");
	if (d) {
	  d+=3;
	  while (*d==' ' || *d=='\t') ++d;
	  *next=malloc(sizeof(struct net));
	  if (!*next) die(1,"out of memory");
	  cur=*next;
	  cur->name="";
	  r=scan_ip6(c,cur->first);
	  if (c[r]!=' ')
	    die(1,"parse error in line ",linenoasc);
	  r=scan_ip6(d,cur->last);
	  if (d[r]!=0)
	    die(1,"parse error in line ",linenoasc);
	}
      }
    } else if (str_start(line,"netname:")) {
      c=line+8;
parsenetname:
      for (; *c==' ' || *c=='\t'; ++c) ;
      if (cur) {
	cur->name=strdup(c);

#if 0
	{
	  char a[FMT_IP6];
	  char b[FMT_IP6];
	  a[fmt_ip6c(a,cur->first)]=0;
	  b[fmt_ip6c(b,cur->last)]=0;
	  buffer_putmflush(buffer_1,"debug: ",a," - ",b," -> \"",cur->name,"\"\n");
	}
#endif
      }
    } else if (str_start(line,"NetRange:")) {
      c=line+9;
      goto parseiprange;
    } else if (str_start(line,"NetName:")) {
      c=line+8;
      goto parsenetname;
    }
  }
  buffer_close(&b);

  lineno=0; whined=0;
  while ((r=buffer_getline(buffer_0,line,sizeof line))>0) {
    char* c=line;
    ++lineno;
    line[r]=0;
    if (line[0]=='@') {		// before tai64nlocal
      if (r<35) goto kaputt;
      c+=26;
      if (*c==' ') ++c;
    } else if (isdigit(line[0]) && line[4]=='-') {	// after tai64nlocal
      c+=30;
      if (r<39) goto kaputt;
      if (*c==' ') ++c;
    } else {
kaputt:
      if (whined != lineno-1) {
	char linenoasc[10];
	linenoasc[fmt_ulong(linenoasc,lineno)]=0;
	carp("parse error on line ",linenoasc);
      }
      whined=lineno;
    }
    if (str_start(c,"GET") || str_start(c,"POST")) {
      char ip[16];
      while (*c && *c!=' ') ++c;
      ++c;
      if (*c=='/')
	die(1,"run gatling log through acc first");
      /* next word is the IP address */
      r=scan_ip6(c,ip);
      if (c[r]!=' ') goto kaputt;

#if 0
	{
	  char a[FMT_IP6];
	  char b[FMT_IP6];
	  a[fmt_ip6c(a,cur->first)]=0;
	  b[fmt_ip6c(b,cur->last)]=0;
	  buffer_putmflush(buffer_1,"debug: ",a," - ",b," -> \"",cur->name,"\"\n");
	}
#endif

      for (cur=root; cur; cur=cur->next) {
	if (!cur->name)
	  die(0,"no netname");
	if (byte_diff(ip,16,cur->first) >= 0 && byte_diff(ip,16,cur->last) <= 0) {
	  buffer_putmflush(buffer_1,line," -> \"",cur->name,"\"\n");
	  break;
	}
      }
    }
  }
  return 0;
}
