#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

int main(int argc,char* argv[]) {
  char salt[2];
  char charset[100];
  unsigned int l,i;
  int fd;
  salt[0]='a';
  salt[1]='b';
  crypt("fnord",salt);
}
