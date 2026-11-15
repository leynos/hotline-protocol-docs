/* config.h.  Generated automatically by configure.  */
/* config.h.in.  Generated automatically from configure.in by autoheader.  */

/* Define to empty if the keyword does not work.  */
/* #undef const */

/* Define as __inline if that's what the C compiler calls it.  */
/* #undef inline */

/* Define if you need to in order for stat and other things to work.  */
/* #undef _POSIX_SOURCE */

/* Define as the return type of signal handlers (int or void).  */
#define RETSIGTYPE void

/* Define to `unsigned' if <sys/types.h> doesn't define.  */
/* #undef size_t */

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if your processor stores words with the most significant
   byte first (like Motorola and SPARC, unlike Intel and VAX).  */
/* #undef WORDS_BIGENDIAN */

/* Define to `long int' if not defined by system */
/* #undef ssize_t */

/* Define if not defined by system
   u_int*_t is an integer type of exactly * bits */
/* #undef u_int8_t */
/* #undef u_int16_t */
/* #undef u_int32_t */
/* #undef int8_t */
/* #undef int16_t */
/* #undef int32_t */

/* Define if snprintf is broken */
#define BROKEN_SNPRINTF 1

/* Define to to use pthreads instead of fork or clone for htxf */
/* #undef CONFIG_HTXF_PTHREAD */

/* Define to to use clone instead of fork for htxf */
/* #undef CONFIG_HTXF_CLONE */

/* Define to use fork instead of clone for htxf */
#define CONFIG_HTXF_FORK 1

/* Define to compile image preview code */
/* #undef CONFIG_HTXF_PREVIEW */

/* Define to enable HFS */
#define CONFIG_HFS 1

/* Define to compile megahal */
/* #undef CONFIG_HAL */

/* Define to compile HOPE */
/* #undef CONFIG_HOPE */

/* Define to compile cipher */
/* #undef CONFIG_CIPHER */

/* Define to compile compress */
/* #undef CONFIG_COMPRESS */

/* Define if you want sql logging */
/* #undef CONFIG_SQL */

/* Define if you have the strcasestr function */
#define HAVE_STRCASESTR 1

/* Define if you have the basename function */
#define HAVE_BASENAME 1

/* Path to tr */
#define PATH_TR "/usr/sbin/tr"

/* Default sound player */
#define DEFAULT_SND_PLAYER "play"

/* Define to compile trackname command */
/* #undef CONFIG_XMMS */

/* Define to dull the icon of a user when the user is away */
/* #undef CONFIG_DULLED */

/* Enable IPv6 Support */
/* #undef CONFIG_IPV6 */

/* Define to detect DARWIN users */
/* #undef DARWIN */

/* Define to detect CARBON API on host */
/* #undef CARBON */

/* Define if you have the getdtablesize function.  */
#define HAVE_GETDTABLESIZE 1

/* Define if you have the gethostname function.  */
#define HAVE_GETHOSTNAME 1

/* Define if you have the getrlimit function.  */
#define HAVE_GETRLIMIT 1

/* Define if you have the hstrerror function.  */
#define HAVE_HSTRERROR 1

/* Define if you have the inet_aton function.  */
#define HAVE_INET_ATON 1

/* Define if you have the inet_ntoa_r function.  */
/* #undef HAVE_INET_NTOA_R */

/* Define if you have the localtime_r function.  */
#define HAVE_LOCALTIME_R 1

/* Define if you have the putenv function.  */
#define HAVE_PUTENV 1

/* Define if you have the snprintf function.  */
#define HAVE_SNPRINTF 1

/* Define if you have the tcgetattr function.  */
#define HAVE_TCGETATTR 1

/* Define if you have the tcsetattr function.  */
#define HAVE_TCSETATTR 1

/* Define if you have the vsnprintf function.  */
#define HAVE_VSNPRINTF 1

/* Define if you have the <stdarg.h> header file.  */
#define HAVE_STDARG_H 1

/* Define if you have the <sys/select.h> header file.  */
#define HAVE_SYS_SELECT_H 1

/* Define if you have the <termcap.h> header file.  */
#define HAVE_TERMCAP_H 1

/* Define if you have the nsl library (-lnsl).  */
/* #undef HAVE_LIBNSL */

/* Define if you have the socket library (-lsocket).  */
/* #undef HAVE_LIBSOCKET */

/* Define if you have the socks5 library (-lsocks5).  */
/* #undef HAVE_LIBSOCKS5 */
