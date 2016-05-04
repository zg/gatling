#ifdef __dietlibc__
#include <md5.h>
#else
#include <openssl/md5.h>
#define MD5Init MD5_Init
#define MD5Update MD5_Update
#define MD5Final MD5_Final
#endif

int main() {
  MD5_CTX md5_ctx;
  MD5Init(&md5_ctx);
  return 0;
}
