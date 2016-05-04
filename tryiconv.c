#include <sys/types.h>
#include <iconv.h>

int main() {
  iconv_t i=iconv_open("UTF-16LE","ISO-8859-1");
  size_t X,Y;
  char* x,* y;
  char src[]="fnord";
  char dest[100];
  X=6;
  Y=sizeof(dest);
  x=src;
  y=dest;
  iconv(i,&x,&X,&y,&Y);
}
