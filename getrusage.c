#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include "buffer.h"

main() {
  struct rusage u;

  if (getrusage(RUSAGE_SELF,&u)==0) {
    buffer_puts(buffer_1,"resident ");
    buffer_putulong(buffer_1,u.ru_maxrss);
    buffer_puts(buffer_1,"\nshared ");
    buffer_putulong(buffer_1,u.ru_ixrss);
    buffer_puts(buffer_1,"\nunshared data ");
    buffer_putulong(buffer_1,u.ru_idrss);
    buffer_puts(buffer_1,"\nstack ");
    buffer_putulong(buffer_1,u.ru_isrss);
    buffer_putnlflush(buffer_1);
  }
}

#if 0
struct rusage {
    struct timeval ru_utime; /* user time used */
    struct timeval ru_stime; /* system time used */
    long   ru_maxrss;        /* maximum resident set size */
    long   ru_ixrss;         /* integral shared memory size */
    long   ru_idrss;         /* integral unshared data size */
    long   ru_isrss;         /* integral unshared stack size */
    long   ru_minflt;        /* page reclaims */
    long   ru_majflt;        /* page faults */
    long   ru_nswap;         /* swaps */
    long   ru_inblock;       /* block input operations */
    long   ru_oublock;       /* block output operations */
    long   ru_msgsnd;        /* messages sent */
    long   ru_msgrcv;        /* messages received */
    long   ru_nsignals;      /* signals received */
    long   ru_nvcsw;         /* voluntary context switches */
    long   ru_nivcsw;        /* involuntary context switches */
};
#endif
