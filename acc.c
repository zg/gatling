#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <buffer.h>
#include <errmsg.h>

size_t hash(const char* word) {
  size_t x;
  for (x=0; *word; ++word)
    x = (x + (x << 5)) ^ *word;
  return x;
}

#define HASHTABSIZE 65536

struct node {
  char* word,* ip,* port,* timestamp;
  struct node* next;
}* hashtab[HASHTABSIZE];

void* allocassert(void* x) {
  if (!x) {
#ifdef oldandslow
    fprintf(stderr,"out of memory!\n");
    exit(1);
#else
    die(1,"out of memory");
#endif
  }
  return x;
}

struct node** lookup(char* word) {
  struct node** x;
  for (x=&hashtab[hash(word)%HASHTABSIZE]; *x; x=&(*x)->next)
    if (!strcmp(word,(*x)->word))
      break;
  return x;
}

char printfbuf[16*1024];

static int cmp3(const char* a, const char* b) {
#if defined(__i386__) || defined(__x86_64__)
  return a[0]==b[0] && a[1]==b[1] && a[2]==b[2];
#else
  return ((*(uint32_t*)a ^ *(uint32_t*)b) & 0xffffff) == 0;
#endif
}

static int cmp4(const char* a, const char* b) {
#if defined(__i386__) || defined(__x86_64__)
  return *(uint32_t*)a == *(uint32_t*)b;
#else
  return cmp3(a,b) && a[3]==b[3];
#endif
}

#ifndef oldandslow
static unsigned char inbuf[16*1024];
static size_t ib_first,ib_last;

static int mygetc() {
  if (ib_first>=ib_last) {
    ib_first=0;
    ib_last=read(0,inbuf,sizeof inbuf);
    if (ib_last==(size_t)-1) return -1;
    if (ib_last==0) return -2;
  }
  return inbuf[ib_first++];
}

static size_t myfgets(char* buf,size_t bufsize) {
  static int eof;
  int i;
  size_t j;
  if (eof) return 0;
  for (j=0; j<bufsize-1; ++j) {
    i=mygetc();
    if (i==-2) { eof=1; return j; }
    if (i==-1) return -1;
    if (i=='\n') break;
    buf[j]=i;
  }
  buf[j]=0;
  return j;
}
#endif

int main() {
  char line[8192];
  char* dat;
  char* timestamp;
#ifdef oldandslow
  setvbuf(stdout,printfbuf,_IOFBF,sizeof printfbuf);
  while (fgets(line,sizeof(line),stdin)) {
    int tslen;
    /* chomp */
    {
      int i;
      for (i=0; i<sizeof(line) && line[i]; ++i)
	if (line[i]=='\n') break;
      line[i]=0;
    }
#else
  buffer_init(buffer_1,write,1,printfbuf,sizeof printfbuf);
  while (myfgets(line,sizeof(line))+1>1) {
    int tslen;
#endif
    /* find out what kind of time stamp there is */
    tslen=0;
    if (line[0]=='@') {
      /* multilog timestamp */
      char* x=strchr(line,' ');
      if (x) {
	tslen=x-line;
	if (tslen!=25) tslen=0;
      }
    } else if (isdigit(line[0])) {
      char* x=strchr(line,' ');
      if (x && x==line+10) {
	x=strchr(x+1,' ');
	if (x && x==line+29) tslen=29;
      }
    }
    if (tslen) {
      dat=line+tslen+1;
      line[tslen]=0;
      timestamp=line;
    } else {
      dat=line;
      timestamp="";
    }
    /* element two is the unique key */
    {
      char* fields[21];
      char* x=dat;
      int i;

      /* early-out skip the field splitting if we are not interested in
       * the line anyway */
      if (*x != 'a' && *x != 'c' && *x != 'G' && *x != 'P' && *x != 'H')
	continue;

      /* split into fields */
      for (i=0; i<20; ++i) {
	char* y=strchr(x,' ');
	if (!y) break;
	*y=0;
	fields[i]=x;
	x=y+1;
      }
      fields[i]=x; ++i;
      if (!strcmp(fields[0],"accept")) {
	struct node** N;
	struct node* x;
	if (i<2) continue;
	N=lookup(fields[1]);
	if (!(x=*N)) {
	  *N=malloc(sizeof(**N));
	  (*N)->next=0;
	  x=*N;
	} else {
	  free(x->word);
#ifdef oldandslow
	  free(x->ip);
	  free(x->port);
	  free(x->timestamp);
#endif
	}
#ifndef oldandslow
	/* reduce allocations */
	x->word=allocassert(malloc((fields[4]-fields[1])+(fields[0]-line)));
	memcpy(x->word,fields[1],fields[4]-fields[1]);
	x->ip=x->word+(fields[2]-fields[1]);
	x->port=x->ip+(fields[3]-fields[2]);
	x->timestamp=x->port+(fields[4]-fields[3]);
	memcpy(x->timestamp,line,fields[0]-line);
#else
	x->word=allocassert(strdup(fields[1]));
	x->ip=allocassert(strdup(fields[2]));
	x->port=allocassert(strdup(fields[3]));
	x->timestamp=allocassert(strdup(line));
#endif
      } else if (!strncmp(fields[0],"close/",6)) {
	struct node** N;
	N=lookup(fields[1]);
	if (*N) {
	  struct node* y=(*N)->next;
	  struct node* x=*N;
	  free(x->word);
#ifdef oldandslow
	  free(x->ip);
	  free(x->port);
	  free(x->timestamp);
#endif
	  free(x);
	  *N=y;
	}
      } else if (cmp3(fields[0],"GET") || cmp4(fields[0],"POST") || cmp4(fields[0],"HEAD")) {
	if (i>6) {	/* otherwise it's a format violation and we ignore the line */
	  struct node** N;
	  N=lookup(fields[1]);
#ifdef oldandslow
	  printf("%s %s %s http%s://%s%s %s %s %s\n",
		 timestamp,fields[0],*N?(*N)->ip:"::",
		 strstr(fields[0],"SSL")?"s":"",fields[6],fields[2],fields[3],fields[4],fields[5]);
#else
	  buffer_putm(buffer_1,timestamp," ",fields[0]," ",*N?(*N)->ip:"::"," http",
		      strstr(fields[0],"SSL")?"s":"","://",fields[6],fields[2]," ",
		      fields[3]," ",fields[4]," ",fields[5],"\n");
#endif
	}
      }
    }
  }
#ifndef oldandslow
  buffer_flush(buffer_1);
#endif
  return 0;
}
