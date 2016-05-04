#include <byte.h>
#include <stdlib.h>
#include <time.h>

unsigned int max_requests_per_minute;

enum { HASHTABLEN=1031 };
static time_t lastpurge;

static struct connection {
  struct connection* next;
  unsigned long connections;
  time_t last;
  char ip[16];
}* root[HASHTABLEN];

static unsigned int hash(const char* ip) {
  int i;
  unsigned int res;
  res=0;
  for (i=0; i<16; ++i)
    res = (res + (res << 5)) ^ ip[i];
  return res%HASHTABLEN;
}

/* returns 0 if the request was added and should be serviced.
 * returns 1 if a denial of service attack from this IP was detected and
 *           the request should not be serviced
 * returns -1 if we ran out of memory trying to add the request */
int new_request_from_ip(const char ip[16],time_t now) {
  struct connection** x, ** base;
  unsigned int i;
  if (!max_requests_per_minute) return 0;
  if (now > lastpurge+60) {
    for (i=0; i<sizeof(root)/sizeof(root[0]); ++i) {
      x=root+i;
      while (*x) {
	struct connection* tmp;
	if ((*x)->last+60 < now ||
	    (*x)->connections <= max_requests_per_minute/10) {	// had a minute of silence or very low volume -> remove
	  tmp=*x;
	  x=&(*x)->next;
	  free(tmp);
	} else {
	  /* halve connections count on record unless they exceed threshold */
	  if ((*x)->connections < max_requests_per_minute)
	    (*x)->connections /= 2;
	  x=&(*x)->next;
	}
      }
    }
    lastpurge=now;
  }
  x=base=root+hash(ip);
  while (*x) {
    if (byte_equal((*x)->ip,16,ip)) {
      int res;
      (*x)->last=now;
      res = (++(*x)->connections > max_requests_per_minute);
      if (x != base) {
	struct connection* tmp=*x;
	*x=(*x)->next;
	tmp->next=*base;
	*base=tmp;
      }
      return res;
    }
    x=&(*x)->next;
  }
  *x=malloc(sizeof(**x));
  if (!*x) return -1;
  (*x)->last=now;
  byte_copy((*x)->ip,16,ip);
  (*x)->connections=1;
  return 0;
}

#if 0
#include <stdio.h>

int main() {
  int i;
  max_requests_per_minute=5;
  for (i=0; i<100; ++i)
    printf("%d\n",new_request_from_ip("0123456789abcdef",23));
}
#endif
