/* this is for catting multilog style @[timestamp] files. */
/* normally if you say
 *   $ cat @40000000447* current
 * then the shell will sort this alphabetically, which will sort
 * @40000000447a before @400000004470, thus messing up the time stamps.
 * If you use hcat instead of cat, hcat will sort these file names
 * hexadecimally and exec cat */
#include <stdlib.h>
#include <unistd.h>

static int fromhex(unsigned char x) {
  x-='0';
  if( x<=9) return x;
  x&=~0x20;
  x-='A'-'0';
  if( x<6 ) return x+10;
  return -1;
  /* more readable but leads to worse code:
  if (x>='a' && x<='z') return x-'a'+10;
  if (x>='A' && x<='Z') return x-'A'+10;
  if (x>='0' && x<='9') return x-'0';
  return -1; */
}

int compar(const void* a,const void* b) {
  const unsigned char* A=*(const unsigned char**)a;
  const unsigned char* B=*(const unsigned char**)b;
  if (*A=='@' && *B=='@') {
    ++A; ++B;
    while (*A && *A==*B) ++A,++B;
    return fromhex(*A) - fromhex(*B);
  } else {
    while (*A && *A==*B) ++A,++B;
    return *A - *B;
  }
}

int main(int argc,char* argv[],char* envp[]) {
  if (argc>1)
    qsort(argv+1,argc-1,sizeof(argv[0]),compar);
  execve("/bin/cat",argv,envp);
  return 1;
}
