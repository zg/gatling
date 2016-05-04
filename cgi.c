#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fmt.h>
#include <scan.h>
#include <socket.h>
#include <getopt.h>
#include <ip6.h>
#include <buffer.h>

#define MAXARGLEN (64*1024)

enum {
  CGI, SCGI, FASTCGI
} cgimode;

/* return content length */
static long do_cgi(char** res) {
  long l=-1;
  *res=0;
  char* method=getenv("REQUEST_METHOD");
  if (method) {
    if (!strcmp(method,"GET")) {
      *res=getenv("QUERY_STRING");
      if (*res)
	l=strlen(*res);
      else
	l=0;
    } else if (!strcmp(method,"POST")) {
      char* x;
      if ((x=getenv("CONTENT_LENGTH"))) {
	l=atol(x);
	if ((l>0) && (l<MAXARGLEN) && (x=malloc(l+1))) {
	  long rest=l;
	  *res=x;
	  while (rest) {
	    long r=read(0,x,rest);
	    if (r<=0) {
	      *res=0;
	      return -1;
	    }
	    rest-=r;
	    x+=r;
	  }
	  *x=0;
	} else
	  l=0;
      }
    }
  }
  return l;
}

int main(int argc,char* argv[],char* envp[]) {
  int i;
  char* c;
  long l;
  unsigned long port;
  (void)argc;
  (void)argv;
  buffer_puts(buffer_1,"Content-Type: text/plain\r\n\r\n");
  l=do_cgi(&c);
  if (l>0) {
    buffer_puts(buffer_1,"CGI arguments:\n\n  --==[snip]==--\n");
    buffer_put(buffer_1,c,l);
    buffer_puts(buffer_1,"\n\n  --==[snip]==--\n\n");
  }
  for (i=0; envp[i]; ++i)
    buffer_putm(buffer_1,envp[i],"\n");
  buffer_flush(buffer_1);
  return 0;
}
