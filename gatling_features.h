#ifndef _GATLING_FEATURES_H
#define _GATLING_FEATURES_H

// #define SUPPORT_MULTIPROC

// #define SUPPORT_BITTORRENT

#define SUPPORT_SERVERSTATUS
#define SUPPORT_SMB
#define SUPPORT_FTP
#define SUPPORT_PROXY
/* #define DEBUG to enable more verbose debug messages for tracking fd
 * leaks */
/* #define DEBUG */
#define SUPPORT_CGI
#define SUPPORT_HTACCESS

/* if a user asks for /foo but foo is a directory, then the default
 * behavior of gatling is 404.  Apache generates a redirect to /foo/.
 * #define this if you want gatling to generate a redirect, too */
#define SUPPORT_DIR_REDIRECT

/* SUPPORT_BZIP2 means gatling will also look for foo.html.bz2 and not
 * just foo.html.gz; however, almost no browsers support this, and if
 * you don't have .bz2 files lying around, it wastes performance, so
 * only enable it if you really have a use for it. */
/* #define SUPPORT_BZIP2 */

/* if you want a redirect instead of a 404, #define this */
#define SUPPORT_FALLBACK_REDIR

/* open files in threads to open kernel I/O scheduling opportunities */
#undef SUPPORT_THREADED_OPEN

/* try to divine MIME type by looking at content */
#define SUPPORT_MIMEMAGIC

/* http header size limit: */
#define MAX_HEADER_SIZE 8192

#ifdef __MINGW32__
#include "windows.h"

#undef SUPPORT_MULTIPROC
#undef SUPPORT_CGI
#undef SUPPORT_PROXY
#undef SUPPORT_FTP
#undef SUPPORT_MIMEMAGIC
#undef USE_ZLIB
#undef SUPPORT_HTACCESS
#include <malloc.h>
#endif

#ifdef SUPPORT_MULTIPROC
#undef SUPPORT_CGI
#endif

#ifdef SUPPORT_THREADED_OPEN
#include <pthread.h>
#endif

#endif
