#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

size_t hash(const char* word) {
  size_t x;
  for (x=0; *word; ++word) {
    x = x*5^*word;
  }
  return x;
}

#define HASHTABSIZE 65536

struct node {
  char* word;
  size_t count;
  struct node* next;
  struct node* pl;
}* hashtab[HASHTABSIZE];

void* allocassert(void* x) {
  if (!x) {
    fprintf(stderr,"out of memory!\n");
    exit(1);
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

void addlist(struct node** N,char* word) {
  while (*N) {
    if (!strcmp((*N)->word,word)) break;
    N=&(*N)->next;
  }
  if (*N) {
    ++(*N)->count;
    return;
  }
  *N=malloc(sizeof(**N));
  (*N)->next=0;
  (*N)->word=strdup(word);
  (*N)->count=1;
}

int compar(const void* a,const void* b) {
  int i = (*(struct node**)b)->count - (*(struct node**)a)->count;
  return (i?i:strcmp((*(struct node**)a)->word,(*(struct node**)b)->word));
}

void sortbycount(struct node** N) {
  size_t i,count;
  struct node* n;
  struct node** x;
  for (count=0, n=*N; n; ++count, n=n->next);
  x=allocassert(malloc(count*sizeof(*x)));
  for (i=0, n=*N; i<count; ++i, n=n->next) x[i]=n;
  qsort(x,count,sizeof(*x),compar);
  for (i=0; i+1<count; ++i)
    x[i]->next=x[i+1];
  x[i]->next=0;
  *N=x[0];
  free(x);
}

int main() {
  char line[8192];
  char* dat;
//  char* timestamp;
  while (fgets(line,sizeof(line),stdin)) {
    int tslen;
    /* chomp */
    {
      int i;
      for (i=0; i<sizeof(line) && line[i]; ++i)
	if (line[i]=='\n') break;
      line[i]=0;
    }
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
//      timestamp=line;
    } else {
      dat=line;
//      timestamp="";
    }
    /* element two is the unique key */
    {
      char* fields[20];
      char* x=dat;
      int i;
      /* split into fields */
      for (i=0; i<20; ++i) {
	char* y=strchr(x,' ');
	if (!y) break;
	*y=0;
	fields[i]=x;
	x=y+1;
      }
      fields[i]=x; ++i;
      /* now process */
      if (i>=6) {
	char* referrer=fields[5];
	char* url=fields[2];
	char* x;
	struct node** N;
//	printf("%s => %s\n",referrer,url);
	/* not interested in access without referrer */
#ifndef ALL
	if (!strcmp(referrer,"[no_referrer]")) continue;
#endif
	/* not interested in empty referrer (early versions of gatling) */
	if (!referrer[0]) continue;
	/* skip method and http://host/ */
	if (!strncmp(url,"http",4)) {
	  x=url+4;
	  if (*x=='s') ++x;
	  if (*x!=':') continue; ++x;
	  if (*x!='/') continue; ++x;
	  if (*x!='/') continue; ++x;
	  x=strchr(x,'/');
	  if (!x) continue;

	  /* now we know how long the http://host part is: x-url */
	  /* if it's the same in url and referrer, we aren't interested */
	  if (!memcmp(referrer,url,x-url)) continue;
	} else continue;
	/* now we're talking! */
	N=lookup(url);
	if (!*N) {
	  *N=calloc(sizeof(**N),1);
	  (*N)->word=allocassert(strdup(url));
	}
	(*N)->count++;
	addlist(&(*N)->pl,referrer);
      } else continue;
    }
  }

  /* now sort urls by count */
  {
    size_t count;
    size_t i;
    struct node** x;
    for (i=count=0; i<HASHTABSIZE; ++i) {
      struct node* n;
      for (n=hashtab[i]; n; n=n->next)
	++count;
    }
    x=malloc(count*sizeof(*x));
    for (i=count=0; i<HASHTABSIZE; ++i) {
      struct node* n;
      for (n=hashtab[i]; n; n=n->next) {
	x[count]=n;
	++count;
      }
    }
    qsort(x,count,sizeof(*x),compar);
    for (i=0; i<count; ++i) {
      struct node* n;
      printf("[%zu] %s\n",x[i]->count,x[i]->word);
      sortbycount(&x[i]->pl);
      for (n=x[i]->pl; n; n=n->next)
	printf("  %4zu => %s\n",n->count,n->word);
      printf("\n");
    }
  }
  return 0;
}
