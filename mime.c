#define _XOPEN_SOURCE 500

#include "gatling.h"

#include "mmap.h"
#include "str.h"
#include "byte.h"

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

struct arena {
  struct arena* next;
  unsigned long n;
  void* ptrs[(4096/sizeof(void*))-2];
};

static void ainit(struct arena* a) {
  a->n=0; a->next=0;
}

static void* amalloc(struct arena* a,size_t n) {
  void* x;
  while (a->n==(sizeof(a->ptrs)/sizeof(a->ptrs[0])) && a->next) a=a->next;
  if (a->n==(sizeof(a->ptrs)/sizeof(a->ptrs[0]))) {
    if (!(a->next=malloc(sizeof(struct arena)))) return 0;
    ainit(a->next);
    a=a->next;
  }
  if ((a->ptrs[a->n]=x=malloc(n))) ++a->n;
  return x;
}

#if 0
static void afree(struct arena* a,void* x) {
  for (; a; a=a->next) {
    unsigned int i;
    for (i=0; i<a->n; ++i)
      if (a->ptrs[i]==x) {
	free(x);
	a->ptrs[i]=a->ptrs[a->n-1];
	--a->n;
      }
  }
}
#endif

static void free_arena(struct arena* a) {
  for (; a; a=a->next) {
    unsigned int i;
    for (i=0; i<a->n; ++i)
      free(a->ptrs[i]);
  }
}


struct pool {
  struct arena a;
  char* dat;
  size_t rest;
};

static void pinit(struct pool* p) {
  ainit(&p->a);
  p->rest=0;
}

static void* pmalloc(struct pool* p,size_t n) {
  void* x;
  if (n>p->rest) {
    if (n>4096) return amalloc(&p->a,n);
    if (!(p->dat=amalloc(&p->a,p->rest=16*1024))) return 0;
  }
  x=p->dat;
  p->dat+=n;
  p->rest-=n;
  return x;
}

static void pfree(struct pool* p) {
  free_arena(&p->a);
}



static const char* nextline(const char* x,const char* end) {
  for (; x<end; ++x)
    if (*x=='\n') return x+1;
  return x;
}

static const char* skipws(const char* x,const char* end) {
  for (; x<end && (*x==' ' || *x=='\t'); ++x) ;
  return x;
}

static const char* skipnonws(const char* x,const char* end) {
  for (; x<end && *x!=' ' && *x!='\t' && *x!='\n'; ++x) ;
  return x;
}

static char* memdup(struct pool* p,const char* x,const char* end) {
  char* y=0;
  if (x<end) {
    y=pmalloc(p,end-x+1);
    if (y) {
      memcpy(y,x,end-x);
      y[end-x]=0;
    }
  }
  return y;
}

static struct mimeentry { const char* name, *type; }* mimetypes;
static struct pool* mimepool;

static void parse_mime_types(const char* filename) {
  size_t maplen;
  const char* map=mmap_read(filename,&maplen);
  unsigned int allocated=0,used=0;
  struct mimeentry* nmt=0;
  if (map) {
    const char* mimetype;
    const char* extension;
    const char* end=map+maplen;
    const char* x,* l;
    struct pool* p=malloc(sizeof(struct pool));
    if (!p) goto kaputt;
    pinit(p);
    for (l=map; l<end; l=nextline(l,end)) {
      x=skipws(l,end);
      if (x>=end) break; if (*x=='#' || *x=='\n') continue;

      mimetype=x;
      x=skipnonws(x,end);
      if (x>=end) break; if (*x=='#' || *x=='\n') continue;

      mimetype=memdup(p,mimetype,x);

      x=skipws(x,end);
      if (x>=end) break; if (*x=='#' || *x=='\n') continue;

      while (x<end) {
	extension=x;
	x=skipnonws(x,end);
	if (x>extension) {
	  extension=memdup(p,extension,x);
	  if (!extension) continue;
//	  printf("%s -> %s\n",extension,mimetype);

	  if (used+1 > allocated) {
	    struct mimeentry* tmp;
	    allocated+=16;
	    tmp=realloc(nmt,allocated*sizeof(nmt[0]));
	    if (!tmp) {
	      free(nmt);
	      pfree(p);
	      free(p);
	      nmt=0;
	      goto kaputt;
	    }
	    nmt=tmp;
	  }
	  nmt[used].name=extension;
	  nmt[used].type=mimetype;
	  ++used;

	}
	x=skipws(x,end);
	if (x>=end || *x=='#' || *x=='\n') break;
      }
      if (x>=end) break;
    }
    if (mimepool) { pfree(mimepool); free(mimepool); }
    mimepool=p;
kaputt:
    mmap_unmap((char*)map,maplen);
  }
  if (nmt) {
    nmt[used].name=nmt[used].type=0;
    free(mimetypes);
    mimetypes=nmt;
  }
}

const char* find_mime_type(const char* extension,const char* filename,time_t now) {
  static time_t last;
  static struct stat lasts;
  unsigned int i;
  if (now>last+10) {
    struct stat cur;
    last=now;
    if (stat(filename,&cur)==0 && cur.st_mtime != lasts.st_mtime) {
      lasts=cur;
      parse_mime_types(filename);
    }
  }
  if (mimetypes)
    for (i=0; mimetypes[i].name; ++i)
      if (!strcmp(mimetypes[i].name,extension))
	return mimetypes[i].type;
  return 0;
}

char* magicelfvalue=(char*)0x23;

struct mimeentry mimetab[] = {
  { "html",	"text/html" },
  { "ico",	"image/x-icon" },
  { "txt",	"text/plain" },
  { "css",	"text/css" },
  { "dvi",	"application/x-dvi" },
  { "ps",	"application/postscript" },
  { "pdf",	"application/pdf" },
  { "gif",	"image/gif" },
  { "png",	"image/png" },
  { "jpeg",	"image/jpeg" },
  { "bild",	"image/jpeg" },
  { "jpg",	"image/jpeg" },
  { "svg",	"image/svg+xml" },
  { "mpeg",	"video/mpeg" },
  { "mpg",	"video/mpeg" },
  { "avi",	"video/x-msvideo" },
  { "mov",	"video/quicktime" },
  { "qt",	"video/quicktime" },
  { "mp3",	"audio/mpeg" },
#ifndef SUPPORT_MIMEMAGIC
  { "ogg",	"audio/ogg" },
  { "opus",	"audio/ogg" },
#endif
  { "wav",	"audio/x-wav" },
  { "pac",	"application/x-ns-proxy-autoconfig" },
  { "sig",	"application/pgp-signature" },
  { "torrent",	"application/x-bittorrent" },
  { "rss",	"application/rss+xml" },
  { "class",	"application/octet-stream" },
  { "js",	"application/x-javascript" },
  { "tar",	"application/x-tar" },
  { "zip",	"application/zip" },
  { "rar",	"application/x-rar-compressed" },
  { "7z",	"application/x-7z-compressed" },
  { "dtd",	"text/xml" },
  { "xml",	"text/xml" },
  { "xbm",	"image/x-xbitmap" },
  { "xpm",	"image/x-xpixmap" },
  { "xwd",	"image/x-xwindowdump" },
  { "text",	"text/plain" },
  { "txt",	"text/plain" },
  { "m3u",	"audio/x-mpegurl" },
  { "htm",	"text/html" },
  { "swf",	"application/x-shockwave-flash" },
  { "md5",	"text/plain" },
  { "wmv",	"video/x-ms-wmv" },
  { "mp4",	"video/mp4" },
  { "m4a",	"audio/mp4" },
  { "nzb",	"application/x-nzb" },
  { "webm",	"video/webm" },
#ifndef SUPPORT_MIMEMAGIC
  { "ogv",	"video/ogg" },
#endif
  { 0 } };

const char* mimetype(const char* filename,int fd) {
  int i,e=str_rchr(filename,'.');
  if (filename[e]) {
    ++e;
    if (mimetypesfilename) {
      const char* x=find_mime_type(filename+e,mimetypesfilename,now.sec.x-4611686018427387914ULL);
      if (x) return x;
    }
    for (i=0; mimetab[i].name; ++i)
      if (str_equal(mimetab[i].name,filename+e))
	return mimetab[i].type;
  }
#ifdef SUPPORT_MIMEMAGIC
  {
    char buf[300];
    int r;
    r=pread(fd,buf,sizeof(buf),0);
    if (r>=1 && buf[0]=='<') {
      if (r>1 && buf[1]=='?') {
	char* c;
	if (r>=100)
	  for (c=buf+1; c<buf+r-5; ++c) {
	    if (*c=='<') {
	      if (c<buf+r-8 && byte_equal(c,8,"<rdf:RDF"))
		return "application/rss+xml";
	      else if (c<buf+r-8 && byte_equal(c,5,"<rss "))
		return "application/rss+xml";
	      else if (c<buf+r-8 && byte_equal(c,5,"<svg "))
		return "image/svg+xml";
	    }
	  }
	return "text/xml";
      } else if (buf[1]=='!' || isalnum(buf[1]))
	return "text/html";
    } else if (r>=5 && byte_equal(buf,4,"GIF9"))
      return "image/gif";
    else if (r>=4 && byte_equal(buf,4,"\x89PNG"))
      return "image/png";
    else if (r>=10 && byte_equal(buf,2,"\xff\xd8"))
      return "image/jpeg";
    else if (r>=5 && byte_equal(buf,5,"%PDF-"))
      return "application/pdf";
    else if (r>=4 && (byte_equal(buf,3,"ID3") || byte_equal(buf,2,"\xff\xfb")))
      return "audio/mpeg";
    else if (r>=200 && byte_equal(buf,4,"OggS")) {
      size_t i;
      for (i=0; i<200-6; ++i)
	if (buf[i]=='t' && byte_equal(buf+i+1,5,"heora"))
	  return "video/ogg";
      return "audio/ogg";
    } else if (r>=4 && byte_equal(buf,4,"RIFF")) {
      if (r>=16 && byte_equal(buf+8,3,"AVI"))
	return "video/x-msvideo";
      else
	return "audio/x-wav";
    } else if (r==100 && byte_equal(buf+4,4,"moov"))
      return "video/quicktime";
    else if (r==100 && byte_equal(buf+4,8,"ftypqt  ") && byte_equal(buf+0x24,4,"moov"))
      return "video/quicktime";
    else if (r==100 && byte_equal(buf+4,7,"ftypmp4"))
      return "video/mp4";
    else if (r>=4 && byte_equal(buf,4,"\x30\x26\xb2\x75"))
      return "video/x-ms-asf";
    else if (r>=4 && (byte_equal(buf,4,"\177ELF") || byte_equal(buf,2,"#!")))
      return magicelfvalue;
  }
#else
  else
    return "text/plain";
#endif
  return "application/octet-stream";
}


#ifdef MIME_MAIN

#include <stdio.h>

int main() {
  unsigned int i;
  parse_mime_types("/etc/mime.types");
  for (i=0; mimetypes[i].name; ++i)
    printf("%s -> %s\n",mimetypes[i].name,mimetypes[i].type);
  printf("\n\n ------\n\n");
  parse_mime_types("/etc/mime.types");
  for (i=0; mimetypes[i].name; ++i)
    printf("%s -> %s\n",mimetypes[i].name,mimetypes[i].type);
  free(mimetypes);
  pfree(mimepool);
  free(mimepool);
  return 0;
}
#endif
