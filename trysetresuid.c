#define _GNU_SOURCE
#include <unistd.h>

int main() {
  setresgid(1,2,3);
  setresuid(1,2,3);
}
