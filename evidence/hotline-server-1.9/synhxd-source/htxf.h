#ifndef __htxf_h
#define __htxf_h

#include "hxd.h"

extern void htxf_init (struct SOCKADDR_IN *saddr);

#if defined(CONFIG_HTXF_PTHREAD)
typedef void * thread_return_type;
#else
typedef int thread_return_type;
#endif

extern thread_return_type get_thread (void *__arg);
extern thread_return_type put_thread (void *__arg);

extern int htxf_thread_create (thread_return_type (*fn)(void *), struct htxf_conn *htxf);
extern void mask_signal (int how, int sig);

extern void htxf_close (int fd);

#endif
