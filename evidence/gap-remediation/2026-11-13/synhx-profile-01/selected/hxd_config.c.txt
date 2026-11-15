#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "hxd.h"
#include "hfs.h"
#ifndef TEST
#include "xmalloc.h"
#else
#define xmalloc(x) malloc(x)
#define xrealloc(x,y) realloc(x,y)
#define xstrdup(x) strdup(x)
#define xfree(x) free(x)
#endif

static char *default_trackers[] = { 0 };
#ifdef CONFIG_IPV6
static char *default_addresses[] = { "::1", 0 };
#else
static char *default_addresses[] = { "0.0.0.0", 0};
#endif
static char *default_logins[] = { "admin", 0 };
static char *default_connect_to[] = { 0 };
static char *default_messagebot[] = { "message delivered by", "message was delivered by" };
static char *default_ciphers[] = { "RC4", "BLOWFISH", "IDEA", 0 };

static struct hxd_config default_hxd_cfg = {
	{ 64, 64, 1, 1, 30, 0, 0, 3, 1},
	{ "./files", "./accounts", "./exec", "./news", "./agreement",
	  "./log", "./banlist", "./tracker_banlist" },
	{ "name", "description", default_trackers, 180, -1, 0 },
	{ 5500, -1, -1, 0, default_addresses, 600, 1 },
	{ 0000, 0600, 0700, 0600, 0700, 0600, 0600 },
	{ default_logins, default_connect_to, 0 },
	{ "ftp.microsoft.com", HFS_FORK_CAP },
	{ "_________________________________________________________",
	  "(%c):", "\r%13.13s:  %s", "\r *** %s %s" },
	{ "localhost", "hxd", "hxd", "hxd" },
	{ 4, 15, 5, default_messagebot },
	{ "/tmp/entropy", default_ciphers }
};

struct hxd_config hxd_cfg;

void
init_hxd_cfg (struct hxd_config *cfg)
{
	*cfg = default_hxd_cfg;
	cfg->paths.files = xstrdup(default_hxd_cfg.paths.files);
	cfg->paths.accounts = xstrdup(default_hxd_cfg.paths.accounts);
	cfg->paths.exec = xstrdup(default_hxd_cfg.paths.exec);
	cfg->paths.news = xstrdup(default_hxd_cfg.paths.news);
	cfg->paths.agreement = xstrdup(default_hxd_cfg.paths.agreement);
	cfg->paths.log = xstrdup(default_hxd_cfg.paths.log);
	cfg->paths.banlist = xstrdup(default_hxd_cfg.paths.banlist);
	cfg->paths.tracker_banlist = xstrdup(default_hxd_cfg.paths.tracker_banlist);
	cfg->tracker.name = xstrdup(default_hxd_cfg.tracker.name);
	cfg->tracker.description = xstrdup(default_hxd_cfg.tracker.description);
	cfg->tracker.trackers = xmalloc(sizeof(char *)*2);
	cfg->tracker.trackers[0] = 0;
	cfg->tracker.password = 0;
	cfg->options.addresses = xmalloc(sizeof(char *)*2);
	cfg->options.addresses[0] = xstrdup(default_hxd_cfg.options.addresses[0]);
	cfg->options.addresses[1] = 0;
	cfg->network.logins = xmalloc(sizeof(char *)*2);
	cfg->network.logins[0] = xstrdup(default_hxd_cfg.network.logins[0]);
	cfg->network.logins[1] = 0;
	cfg->network.connect_to = xmalloc(sizeof(char *));
	cfg->network.connect_to[0] = 0;
	cfg->files.comment = xstrdup(default_hxd_cfg.files.comment);
	cfg->strings.news_divider = xstrdup(default_hxd_cfg.strings.news_divider);
	cfg->strings.news_time_fmt = xstrdup(default_hxd_cfg.strings.news_time_fmt);
	cfg->strings.chat_fmt = xstrdup(default_hxd_cfg.strings.chat_fmt);
	cfg->strings.chat_opt_fmt = xstrdup(default_hxd_cfg.strings.chat_opt_fmt);
	cfg->sql.host = xstrdup(default_hxd_cfg.sql.host);
	cfg->sql.user = xstrdup(default_hxd_cfg.sql.user);
	cfg->sql.pass = xstrdup(default_hxd_cfg.sql.pass);
	cfg->sql.data = xstrdup(default_hxd_cfg.sql.data);
	cfg->spam.messagebot = xmalloc(sizeof(char *)*3);
	cfg->spam.messagebot[0] = xstrdup(default_hxd_cfg.spam.messagebot[0]);
	cfg->spam.messagebot[1] = xstrdup(default_hxd_cfg.spam.messagebot[1]);
	cfg->spam.messagebot[2] = 0;
	cfg->cipher.egd_path = xstrdup(default_hxd_cfg.cipher.egd_path);
	cfg->cipher.ciphers = xmalloc(sizeof(char *)*4);
	cfg->cipher.ciphers[0] = xstrdup(default_hxd_cfg.cipher.ciphers[0]);
	cfg->cipher.ciphers[1] = xstrdup(default_hxd_cfg.cipher.ciphers[1]);
	cfg->cipher.ciphers[2] = xstrdup(default_hxd_cfg.cipher.ciphers[2]);
	cfg->cipher.ciphers[3] = 0;
}

#define WANT_INT	1
#define WANT_INT_OCTAL	2
#define WANT_STR	3
#define WANT_STR_ARRAY	4
#define WANT_BOOL	5
#define WANT_FORK	6

struct wanted {
	char *str;
	int type, off;
	struct wanted *next, *prev;
	char *begin;
};

static struct wanted wanted_limits[] = {
	{ "total_downloads", WANT_INT, 0, 0, 0, 0 },
	{ "total_uploads", WANT_INT, sizeof(long), 0, 0, 0 },
	{ "individual_downloads", WANT_INT, sizeof(long)*2, 0, 0, 0 },
	{ "individual_uploads", WANT_INT, sizeof(long)*3, 0, 0, 0 },
	{ "queue_size", WANT_INT, sizeof(long)*4, 0, 0, 0 },
	{ "can_omit_queue", WANT_INT, sizeof(long)*5, 0, 0, 0 },
	{ "out_Bps", WANT_INT, sizeof(long)*6, 0, 0, 0 },
	{ "total_exec", WANT_INT, sizeof(long)*7, 0, 0, 0 },
	{ "individual_exec", WANT_INT, sizeof(long)*8, 0, 0, 0 },
	{ 0, 0, 0, 0, 0, 0 }
};

static struct wanted wanted_paths[] = {
	{ "files", WANT_STR, sizeof(struct hxd_config_limits), 0, 0, 0 },
	{ "accounts", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(char *), 0, 0, 0 },
	{ "exec", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(char *)*2, 0, 0, 0 },
	{ "news", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(char *)*3, 0, 0, 0 },
	{ "agreement", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(char *)*4, 0, 0, 0 },
	{ "log", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(char *)*5, 0, 0, 0 },
	{ "banlist", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(char *)*6, 0, 0, 0 },
	{ "tracker_banlist", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(char *)*7, 0, 0, 0 },
	{ 0, 0, 0, 0, 0, 0 }
};

static struct wanted wanted_tracker[] = {
	{ "name", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths), 0, 0, 0 },
	{ "description", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(char *), 0, 0, 0 },
	{ "trackers", WANT_STR_ARRAY, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(char *)*2, 0, 0, 0 },
	{ "interval", WANT_INT, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(char *)*2+sizeof(char **), 0, 0, 0 },
	{ "nusers", WANT_INT, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(char *)*2+sizeof(char **)+sizeof(long), 0, 0, 0 },
	{ "password", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(char *)*2+sizeof(char **)+sizeof(long)*2, 0, 0, 0 },
	{ 0, 0, 0, 0, 0, 0 }
};

static struct wanted wanted_options[] = {
	{ "port", WANT_INT, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker), 0, 0, 0 },
	{ "uid", WANT_INT, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(long), 0, 0, 0 },
	{ "gid", WANT_INT, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(long)*2, 0, 0, 0 },
	{ "detach", WANT_BOOL, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(long)*3, 0, 0, 0 },
	{ "addresses", WANT_STR_ARRAY, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(long)*4, 0, 0, 0 },
	{ "away_time", WANT_INT, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(long)*4+sizeof(char **), 0, 0, 0 },
	{ "ident", WANT_INT, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(long)*4+sizeof(char **)+sizeof(long), 0, 0, 0 },
	{ 0, 0, 0, 0, 0, 0 }
};

static struct wanted wanted_permissions[] = {
	{ "umask", WANT_INT_OCTAL, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options), 0, 0, 0 },
	{ "files", WANT_INT_OCTAL, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(long), 0, 0, 0 },
	{ "directories", WANT_INT_OCTAL, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(long)*2, 0, 0, 0 },
	{ "account_files", WANT_INT_OCTAL, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(long)*3, 0, 0, 0 },
	{ "account_directories", WANT_INT_OCTAL, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(long)*4, 0, 0, 0 },
	{ "log_files", WANT_INT_OCTAL, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(long)*5, 0, 0, 0 },
	{ "news_files", WANT_INT_OCTAL, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(long)*6, 0, 0, 0 },
	{ 0, 0, 0, 0, 0, 0 }
};

static struct wanted wanted_network[] = {
	{ "logins", WANT_STR_ARRAY, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions), 0, 0, 0 },
	{ "connect_to", WANT_STR_ARRAY, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(char **), 0, 0, 0 },
	{ "server_id", WANT_INT, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(char **)*2, 0, 0, 0 },
	{ 0, 0, 0, 0, 0, 0 }
};

static struct wanted wanted_files[] = {
	{ "comment", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network), 0, 0, 0 },
	{ "fork", WANT_FORK, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(char *), 0, 0, 0 },
	{ 0, 0, 0, 0, 0, 0 }
};

static struct wanted wanted_strings[] = {
	{ "news_divider", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(struct hxd_config_files), 0, 0, 0 },
	{ "news_time_format", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(struct hxd_config_files)+sizeof(char *), 0, 0, 0 },
	{ "chat_format", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(struct hxd_config_files)+sizeof(char *)*2, 0, 0, 0 },
	{ "chat_opt_format", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(struct hxd_config_files)+sizeof(char *)*3, 0, 0, 0 },
	{ 0, 0, 0, 0, 0, 0 }
};

static struct wanted wanted_sql[] = {
	{ "host", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(struct hxd_config_files)+sizeof(struct hxd_config_strings), 0, 0, 0 },
	{ "user", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(struct hxd_config_files)+sizeof(struct hxd_config_strings)+sizeof(char *), 0, 0, 0 },
	{ "pass", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(struct hxd_config_files)+sizeof(struct hxd_config_strings)+sizeof(char *)*2, 0, 0, 0 }, 
	{ "data", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(struct hxd_config_files)+sizeof(struct hxd_config_strings)+sizeof(char *)*3, 0, 0, 0 },
	{ 0, 0, 0, 0, 0, 0 } 
};

static struct wanted wanted_spam[] = {
	{ "conn_max", WANT_INT, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(struct hxd_config_files)+sizeof(struct hxd_config_strings)+sizeof(struct hxd_config_sql), 0, 0, 0 },
	{ "chat_count", WANT_INT, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(struct hxd_config_files)+sizeof(struct hxd_config_strings)+sizeof(struct hxd_config_sql)+sizeof(long), 0, 0, 0 },
	{ "chat_time", WANT_INT, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(struct hxd_config_files)+sizeof(struct hxd_config_strings)+sizeof(struct hxd_config_sql)+sizeof(long)*2, 0, 0, 0 },
	{ "messagebot", WANT_STR_ARRAY, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(struct hxd_config_files)+sizeof(struct hxd_config_strings)+sizeof(struct hxd_config_sql)+sizeof(long)*3, 0, 0, 0 },
};

static struct wanted wanted_cipher[] = {
	{ "egd_path", WANT_STR, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(struct hxd_config_files)+sizeof(struct hxd_config_strings)+sizeof(struct hxd_config_sql)+sizeof(struct hxd_config_spam), 0, 0, 0 },
	{ "ciphers", WANT_STR_ARRAY, sizeof(struct hxd_config_limits)+sizeof(struct hxd_config_paths)+sizeof(struct hxd_config_tracker)+sizeof(struct hxd_config_options)+sizeof(struct hxd_config_permissions)+sizeof(struct hxd_config_network)+sizeof(struct hxd_config_files)+sizeof(struct hxd_config_strings)+sizeof(struct hxd_config_sql)+sizeof(struct hxd_config_spam)+sizeof(char *), 0, 0, 0 },
};

struct wanted wanted_top[] = {
	{ "limits", 0, 0, wanted_limits, 0, 0 },
	{ "paths",  0, 0, wanted_paths, 0, 0 },
	{ "tracker", 0, 0, wanted_tracker, 0, 0 },
	{ "options", 0, 0, wanted_options, 0, 0 },
	{ "permissions", 0, 0, wanted_permissions, 0, 0 },
	{ "network", 0, 0, wanted_network, 0, 0 },
	{ "files", 0, 0, wanted_files, 0, 0 },
	{ "strings", 0, 0, wanted_strings, 0, 0 },
	{ "sql", 0, 0, wanted_sql, 0, 0 },
	{ "spam", 0, 0, wanted_spam, 0, 0 },
	{ "cipher", 0, 0, wanted_cipher, 0, 0 },
	{ 0, 0, 0, 0, 0, 0 }
};

static int
chrexpand (char *str, int len)
{
	char *p;
	int off;

	p = str;
	off = 1;
	switch (p[1]) {
		case 'r':
			p[1] = '\r';
			break;
		case 'n':
			p[1] = '\n';
			break;
		case 't':
			p[1] = '\t';
			break;
		case 'x':
			while (isxdigit(p[off+1]) && off < 3)
				off++;
			p[off] = (char)strtoul(p+2, 0, 16);
			break;
		default:
			if (!isdigit(p[1]) || p[1] >= '8')
				break;
			while ((isdigit(p[off+1]) && p[off+1] < '8') && off < 3)
				off++;
			p[off] = (char)strtoul(p+2, 0, 8);
			break;
	}
	len -= off;
	memcpy(p, p+off, len);
	p[len] = 0;

	return off;
}

void
hxd_read_config (char *file, void *__mem)
{
	int fd, r, line, l, xxx, comment, lastlinelen;
	char buf[1024], *p, *lastlinep, *mem = (char *)__mem;
	struct wanted *wanted, *w, *last_wanted;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return;
	line = 1;
	comment = 1;
	xxx = 0;
	last_wanted = w = wanted = wanted_top;
	lastlinep = p = buf;
	for (;;) {
		lastlinelen = p - lastlinep;
		if (lastlinelen) {
			memcpy(buf, lastlinep, lastlinelen);
			w->begin = buf+(w->begin-lastlinep);
		}
		r = read(fd, buf+lastlinelen, sizeof(buf)-lastlinelen);
		if (r <= 0)
			break;
		r += lastlinelen;
		for (p = buf; p < buf + r; p++) {
			if (isspace(*p)) {
				if (*p == '\n') {
					lastlinep = p+1;
					line++;
					comment = 1;
				}
				continue;
			}
			if (comment == 2)
				continue;
			if (*p == '#' && comment == 1) {
				comment = 2;
				continue;
			} else if (*p == ';') {
				switch (w->type) {
					case 0:
						break;
					case WANT_INT:
						*((long *)(mem+w->off)) = strtol(w->begin, 0, 0);
						break;
					case WANT_INT_OCTAL:
						*((long *)(mem+w->off)) = strtol(w->begin, 0, 8);
						break;
					case WANT_STR:
						*p = 0;
						{
						char *ptr;
						int len;

						memcpy(&ptr, mem+w->off, sizeof(char *));
						len = (p - w->begin) + 1;
						if (*(p-1) == '"') {
							*(p-1) = 0;
							len--;
						}
						if (w->begin[0] == '"') {
							w->begin++;
							len--;
						}
						ptr = xrealloc(ptr, len);
						memcpy(ptr, w->begin, len);
						memcpy(mem+w->off, &ptr, sizeof(char *));
						}
						break;
					case WANT_STR_ARRAY:
						{
						char **arr;
						char *xp, *beg;
						unsigned int nstrs;

						memcpy(&arr, mem+w->off, sizeof(char **));
						if (arr) {
							int i;
							for (i = 0; arr[i]; i++)
								xfree(arr[i]);
						}
						nstrs = 0;
						for (xp = beg = w->begin; xp <= p; xp++) {
							if (*xp == ',' || *xp == ';') {
								if (*(xp-1) == '"')
									*(xp-1) = 0;
								*xp++ = 0;
								if (*beg == '"')
									beg++;
								arr = xrealloc(arr, sizeof(char *)*(nstrs+1));
								arr[nstrs] = xstrdup(beg);
								while (isspace(*xp)) xp++;
								beg = xp;
								nstrs++;
							}
						}
						arr = xrealloc(arr, sizeof(char *)*(nstrs+1));
						arr[nstrs] = 0;
						memcpy(mem+w->off, &arr, sizeof(char **));
						}
						break;
					case WANT_BOOL:
						*p = 0;
						if (isdigit(*(w->begin)))
							*((long *)(mem+w->off)) = strtoul(w->begin, 0, 0);
						else if (!strcmp(w->begin, "true")
							 || !strcmp(w->begin, "on")
							 || !strcmp(w->begin, "ja")
							 || !strcmp(w->begin, "yes")
							 || !strcmp(w->begin, "si")
							 || !strcmp(w->begin, "oui"))
							*((long *)(mem+w->off)) = 1;
						else
							*((long *)(mem+w->off)) = 0;
						break;
					case WANT_FORK:
						*p = 0;
						if (!strcmp(w->begin, "cap"))
							*((long *)(mem+w->off)) = HFS_FORK_CAP;
						else if (!strcmp(w->begin, "double"))
							*((long *)(mem+w->off)) = HFS_FORK_DOUBLE;
						else if (!strcmp(w->begin, "netatalk"))
							*((long *)(mem+w->off)) = HFS_FORK_NETATALK;
						break;
				}
				comment = 1;
				xxx = 0;
				continue;
			} else if (*p == '{') {
				continue;
			} else if (*p == '}') {
				if (wanted->prev)
					w = wanted = last_wanted;
				continue;
			} else if (*p == '\\') {
				r -= chrexpand(p, (buf+r)-p);
			}
			if (xxx)
				continue;
			for (w = wanted; w->str; w++) {
				l = strlen(w->str);
				if (!memcmp(p, w->str, l) && isspace(*(p+l))) {
					if (w->type == 0 && w->next) {
						w->next->prev = w;
						last_wanted = wanted;
						w = wanted = w->next;
					} else if (w->type) {
						comment = 0;
						xxx = 1;
					}
					p += l;
					while (isspace(*p))
						if (*p++ == '\n') line++;
					w->begin = p--;
					break;
				}
			}
		}
	}
	close(fd);
}

#ifdef TEST
#include <stdio.h>

int
main (int argc, char **argv)
{
	hxd_read_config(argv[1] ? argv[1] : "./hxd.conf", &hxd_cfg);
	printf("limits: %ld %ld %ld %ld\n", hxd_cfg.limits.total_downloads, hxd_cfg.limits.total_uploads,
					hxd_cfg.limits.individual_downloads, hxd_cfg.limits.individual_uploads);
	printf("paths: %s %s %s %s %s %s %s %s\n", hxd_cfg.paths.files, hxd_cfg.paths.accounts, hxd_cfg.paths.exec,
					hxd_cfg.paths.news, hxd_cfg.paths.agreement, hxd_cfg.paths.log, hxd_cfg.paths.banlist,
					hxd_cfg.paths.tracker_banlist);
	printf("permissions: %lo %lo %lo %lo %lo %lo\n", hxd_cfg.permissions.files, hxd_cfg.permissions.directories,
						hxd_cfg.permissions.account_files, hxd_cfg.permissions.account_directories,
						hxd_cfg.permissions.log_files, hxd_cfg.permissions.news_files);
	printf("tracker: %s %s %ld %ld\ntracker addresses:\n", hxd_cfg.tracker.name, hxd_cfg.tracker.description,
					hxd_cfg.tracker.interval, hxd_cfg.tracker.nusers);
	{
		char **p = hxd_cfg.tracker.trackers;
		while (p && *p)
			printf("%s\n", *p++);
	}
	printf("port: %ld\naddresses:\n", hxd_cfg.options.htls_port);
	{
		char **p = hxd_cfg.options.addresses;
		while (p && *p)
			printf("%s\n", *p++);
	}
	printf("network logins:");
	{
		char **p = hxd_cfg.network.logins;
		while (p && *p)
			printf(" %s", *p++);
		printf("\n");
	}
	printf("connect_to:\n");
	{
		char **p = hxd_cfg.network.connect_to;
		while (p && *p)
			printf("%s\n", *p++);
	}
	printf("server_id: %ld\n", hxd_cfg.network.server_id);
	printf("tracker password: %s\n", hxd_cfg.tracker.password);
	printf("tracker password: %s\n", hxd_cfg.tracker.password);
	printf("away_time: %ld\n", hxd_cfg.options.away_time);
	printf("ident: %ld\n", hxd_cfg.options.ident);
	printf("uid: %ld; gid: %ld; detach: %ld\n", hxd_cfg.options.uid, hxd_cfg.options.gid, hxd_cfg.options.detach);
	printf("news_divider: %s\n", hxd_cfg.strings.news_divider);
	printf("news_time_format: %s\n", hxd_cfg.strings.news_time_fmt);
	printf("chat_format: %s chat_opt_format: %s\n", hxd_cfg.strings.chat_fmt, hxd_cfg.strings.chat_opt_fmt);

	printf("sql host: %s\n", hxd_cfg.sql.host);
	printf("sql user: %s\n", hxd_cfg.sql.user);
	printf("sql pass: %s\n", hxd_cfg.sql.pass);
	printf("sql data: %s\n", hxd_cfg.sql.data);

	printf("chat_count/chat_time: %ld/%ld\n", hxd_cfg.spam.chat_count, hxd_cfg.spam.chat_time);
	printf("messagebot:\n");
	{
		char **p = hxd_cfg.spam.messagebot;
		while (p && *p)
			printf("%s\n", *p++);
	}

	printf("egd_path: %s\n", hxd_cfg.cipher.egd_path);
	printf("ciphers:");
	{
		char **p = hxd_cfg.cipher.ciphers;
		while (p && *p)
			printf(" %s", *p++);
		printf("\n");
	}

	return 0;
}
#endif
