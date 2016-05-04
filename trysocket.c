#ifdef __MINGW32__
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

main() {
  int fd=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
}
