#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include "hxd.h"
#include "htxf.h"
#include "xmalloc.h"
#ifdef CONFIG_HOPE
#include "md5.h"
#include "sha.h"
#include "haval.h"
#endif
#ifdef SOCKS
#include "socks.h"
#endif
#ifdef CONFIG_HFS
#include "hfs.h"
#endif

#define HTXF_THREADS_LISTEN	0

#if !defined(NAME_MAX) && defined(FILENAME_MAX)
#define NAME_MAX FILENAME_MAX
#endif

#if defined(__hpux__) && NAME_MAX == 14
#define NAME_MAX 255
#endif

#ifdef CONFIG_HTXF_PREVIEW
#include "magick/magick.h"
#endif

#define COPY_BUFSIZE		0xf000
#define DIRCHAR			'/'
#define ROOTDIR			(htlc->rootdir)

#define log_list	0
#define log_comment	0
#define log_rename	1
#define log_move	1
#define log_mkdir	1
#define log_symlink	1
#define log_delete	1
#define log_getinfo	0
#define log_hash	0
#define log_download	1
#define log_upload	1

u_int16_t nr_gets = 0;
u_int16_t nr_puts = 0;
#if defined(CONFIG_HTXF_QUEUE)
u_int16_t nr_queued = 0;
#endif

static int
hldir_to_path (struct hl_data_hdr *dh, const char *root, char *rlpath, char *pathp)
{
	u_int16_t rootlen, pos, count, dh_len;
	u_int8_t *p, nlen;
	char path[MAXPATHLEN];
	int err = 0;

	rootlen = pos = strlen(root);
	memcpy(path, root, pos);
	path[pos++] = DIRCHAR;
	L16NTOH(count, dh->data);
	if (count > 32)
		count = 32;
	/* compatibility with broken hx */
	L16NTOH(dh_len, &dh->len);
	if (dh_len < 5) {
		strcpy(rlpath, root);
		return 0;
	}
	p = &dh->data[4];
	for (;;) {
		nlen = *p++;
		if (pos + nlen >= MAXPATHLEN) {
			return ENAMETOOLONG;
		}
		if (!(nlen == 2 && p[0] == '.' && p[1] == '.') && !memchr(p, DIRCHAR, nlen)) {
			memcpy(&path[pos], p, nlen);
			pos += nlen;
		}
		if (--count) {
			path[pos++] = DIRCHAR;
			p += 2 + nlen;
		} else {
			path[pos] = 0;
			break;
		}
	}
	if (!realpath(path, rlpath))
		err = errno;
	path[MAXPATHLEN-1] = 0;
	strcpy(pathp, path);

	return err;
}

static void
read_filename (char *filename, const char *in, size_t len)
{
	if ((len == 2 && in[0] == '.' && in[1] == '.') || memchr(in, DIRCHAR, len)) {
		len = 0;
	} else {
		memcpy(filename, in, len);
	}
	filename[len] = 0;
}

#ifdef CONFIG_HTXF_PREVIEW
static int
preview_path (char *previewpath, const char *path, struct stat *statbuf)
{
	int i, len;
	char pathbuf[MAXPATHLEN];
	struct stat sb;

	len = strlen(path);
	if (len + 16 >= MAXPATHLEN)
		return ENAMETOOLONG;
	strcpy(pathbuf, path);
	for (i = len - 1; i > 0; i--)
		if (pathbuf[i] == DIRCHAR) {
			pathbuf[i++] = 0;
			break;
		}

	snprintf(previewpath, MAXPATHLEN, "%s/.preview", pathbuf);
	if (stat(previewpath, &sb)) {
		if (statbuf)
			return ENOENT;
		if (mkdir(previewpath, hxd_cfg.permissions.directories))
			return errno;
	}
	pathbuf[--i] = DIRCHAR;
	strcat(previewpath, &pathbuf[i]);
	if (statbuf && stat(previewpath, statbuf))
		return errno;

	return 0;
}
#endif

static void
snd_file_list (struct htlc_conn *htlc, struct hl_filelist_hdr **fhdrs, u_int16_t fhdrcount)
{
	struct hl_hdr h;
	u_int16_t i;
	u_int32_t pos, this_off, len = SIZEOF_HL_HDR;

	h.type = htonl(HTLS_HDR_TASK);
	h.trans = htonl(htlc->trans);
	htlc->trans++;
	h.flag = 0;
	h.hc = htons(fhdrcount);

	for (i = 0; i < fhdrcount; i++)
		len += SIZEOF_HL_FILELIST_HDR + ntohl(fhdrs[i]->fnlen);
	h.len = htonl(len - (SIZEOF_HL_HDR - sizeof(h.hc)));
#ifdef CONFIG_NETWORK
	if (htlc->server_htlc) {
		struct hl_net_hdr *nh = (struct hl_net_hdr *)&h;
		nh->src = htons(g_my_sid<<10);
		nh->dst = htons(mangle_uid(htlc));
	} else
#endif
		h.len2 = h.len;
	pos = htlc->out.pos + htlc->out.len;
	this_off = pos;
	qbuf_set(&htlc->out, htlc->out.pos, htlc->out.len + len);
	memcpy(&htlc->out.buf[pos], &h, SIZEOF_HL_HDR);
	pos += SIZEOF_HL_HDR;
	FD_SET(htlc->fd, &hxd_wfds);
	for (i = 0; i < fhdrcount; i++) {
		memcpy(&htlc->out.buf[pos], fhdrs[i], SIZEOF_HL_FILELIST_HDR + ntohl(fhdrs[i]->fnlen));
		pos += SIZEOF_HL_FILELIST_HDR + ntohl(fhdrs[i]->fnlen);
	}
	len = pos - this_off;
#ifdef CONFIG_COMPRESS
	if (htlc->compress_encode_type != COMPRESS_NONE)
		len = compress_encode(htlc, this_off, len);
#endif
#ifdef CONFIG_CIPHER
	if (htlc->cipher_encode_type != CIPHER_NONE)
		cipher_encode(htlc, this_off, len);
#endif
}

static int
fh_compare (const void *p1, const void *p2)
{
	struct hl_filelist_hdr *fh1 = *(struct hl_filelist_hdr **)p1, *fh2 = *(struct hl_filelist_hdr **)p2;
	int i, len1, len2, minlen;
	char *n1, *n2;

	n1 = fh1->fname;
	n2 = fh2->fname;
	len1 = ntohl(fh1->fnlen);
	len2 = ntohl(fh2->fnlen);
	minlen = len1 > len2 ? len2 : len1;
	for (i = 0; i < minlen; i++) {
		if (n1[i] > n2[i])
			return 1;
		else if (n1[i] != n2[i])
			return -1;
	}
	if (len1 > len2)
		return 1;
	else if (len1 != len2)
		return -1;

	return 0;
}

static inline void
fh_sort (struct hl_filelist_hdr **fhdrs, u_int16_t count)
{
#if WANT_TO_TIME_SORT
	static int use_qsort = 1;
	struct timeval start, now;
	double diff;
	char secsbuf[32];

	if (use_qsort) {
		gettimeofday(&start, 0);
		qsort(fhdrs, count, sizeof(struct hl_filelist_hdr *), fh_compare);
		gettimeofday(&now, 0);
	} else {
		u_int16_t i, j;
		struct hl_filelist_hdr *fhp;

		gettimeofday(&start, 0);
		for (i = 0; i < count; i++)
			for (j = 1; j < count - i; j++)
				if (fhdrs[j - 1]->fname[0] > fhdrs[j]->fname[0]) {
					fhp = fhdrs[j - 1];
					fhdrs[j - 1] = fhdrs[j];
					fhdrs[j] = fhp;
				}
		gettimeofday(&now, 0);
	}
	diff = (double)(now.tv_sec + now.tv_usec * 0.000001)
	     - (double)(start.tv_sec + start.tv_usec * 0.000001);
	sprintf(secsbuf, "%g", diff);
	hxd_log("%ssort %u took %s seconds", use_qsort ? "q" : "bubble ", count, secsbuf);
	use_qsort = !use_qsort;
#else
	qsort(fhdrs, count, sizeof(struct hl_filelist_hdr *), fh_compare);
#endif
}

static void
hxd_scandir (struct htlc_conn *htlc, const char *path)
{
	DIR *dir;
	struct dirent *de;
	struct hl_filelist_hdr **fhdrs = 0;
	u_int16_t count = 0, maxcount = 0;
	struct stat sb;
	int is_link;
	char pathbuf[MAXPATHLEN];
	u_int8_t nlen;
	
	if (!(dir = opendir(path))) {
		snd_strerror(htlc, errno);
		return;
	}
	while ((de = readdir(dir))) {
		if (count >= maxcount) {
			maxcount += 16;
			fhdrs = xrealloc(fhdrs, sizeof(struct hl_filelist_hdr *) * maxcount);
		}

		/* added to the below conditional so that the user does not see
		 * Macintosh specific files and folders. --Devin */
		
		if (de->d_name[0] == '.' || !strncmp(de->d_name, "Icon\r", 5) || !strncmp(de->d_name, "Network Trash Folder", 20) || !strncmp(de->d_name, "Temporary Items", 15) || !strncmp(de->d_name, "TheFindByContentFolder", 22) || !strncmp(de->d_name, "TheVolumeSettingsFolder", 23))
			continue;
		nlen = (u_int8_t)strlen(de->d_name);
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", path, de->d_name);
		fhdrs[count] = xmalloc(SIZEOF_HL_FILELIST_HDR + nlen);
		fhdrs[count]->type = htons(HTLS_DATA_FILE_LIST);
		fhdrs[count]->len = htons((SIZEOF_HL_FILELIST_HDR - 4) + nlen);
		fhdrs[count]->unknown = 0;
		fhdrs[count]->fnlen = htonl((u_int32_t)nlen);
		memcpy(fhdrs[count]->fname, de->d_name, nlen);
		if (lstat(pathbuf, &sb)) {
fark:		/* symbolic link cannot be resolved */
			fhdrs[count]->fsize = 0;
			fhdrs[count]->ftype = htonl(0x616c6973);	/* 'alis' */
			fhdrs[count]->fcreator = 0;
			count++;
			continue;
		}

		if (S_ISLNK(sb.st_mode)) {
		
			is_link = 1;
			if (stat(pathbuf, &sb))
				goto fark;
				
/*			uid = htons(mangle_uid(htlc));
			hlwrite(htlc, HTLS_HDR_MSG, 0, 3,
				HTLS_DATA_UID, sizeof(uid), &uid,
				HTLS_DATA_MSG, strlen(path), path,
				HTLS_DATA_NAME, 3, "hxd");	
*/
		} else {
			is_link = 0;
		}
		if (S_ISDIR(sb.st_mode)) {
			u_int32_t ndirs = 0;
			DIR *subdir;
			struct dirent *subde;
			if ((subdir = opendir(pathbuf))) {
				while ((subde = readdir(subdir)))
					if (subde->d_name[0] != '.')
						ndirs++;
				closedir(subdir);
			}
			fhdrs[count]->fsize = htonl(ndirs);
			fhdrs[count]->ftype = htonl(0x666c6472);	/* 'fldr' */
			fhdrs[count]->fcreator = 0;
		} else {
			u_int32_t size = sb.st_size;
#if defined(CONFIG_HFS)
			size += resource_len(pathbuf);
#endif
			fhdrs[count]->fsize = htonl(size);
#if defined(CONFIG_HFS)
			type_creator((u_int8_t *)&fhdrs[count]->ftype, pathbuf);
#else
			fhdrs[count]->ftype = 0;
			fhdrs[count]->fcreator = 0;
#endif
		}
		count++;
	}
	closedir(dir);
	fh_sort(fhdrs, count);
	snd_file_list(htlc, fhdrs, count);
	while (count)
		xfree(fhdrs[--count]);
	xfree(fhdrs);
}

static int
check_dropbox (struct htlc_conn *htlc, char *path)
{
	if (!htlc->access.view_drop_boxes && strcasestr(path, "DROP BOX") && strcmp(path, htlc->dropbox))
		return 1;
	return 0;
}

void
rcv_file_list (struct htlc_conn *htlc)
{
	char rlpath[MAXPATHLEN], path[MAXPATHLEN];
	int err;

	if (htlc->in.pos == SIZEOF_HL_HDR) {
		hxd_scandir(htlc, ROOTDIR);
		return;
	}
	dh_start(htlc)
		if (dh_type != HTLC_DATA_DIR)
			return;
		if ((err = hldir_to_path(dh, ROOTDIR, rlpath, path))) {
			snd_strerror(htlc, err);
			return;
		}
		if (check_dropbox(htlc, path)) {
			/* snd_strerror(htlc, EPERM); */
			hlwrite(htlc, HTLS_HDR_TASK, 0, 0);
			return;
		}
		if (log_list)
			hxd_log("%s:%s:%u - list %s", htlc->name, htlc->login, htlc->uid, path);
		hxd_scandir(htlc, rlpath);
	dh_end()
}

void
rcv_file_setinfo (struct htlc_conn *htlc)
{
	u_int16_t fnlen = 0, newfnlen = 0, comlen = 0;
	char dir[MAXPATHLEN], oldbuf[MAXPATHLEN], newbuf[MAXPATHLEN],
	     filename[NAME_MAX], newfilename[NAME_MAX];
	char rsrcpath_old[MAXPATHLEN], rsrcpath_new[MAXPATHLEN];
	u_int8_t comment[200];
	struct stat sb;
	int err;

	dir[0] = 0;

	dh_start(htlc)
		switch (dh_type) {
			case HTLC_DATA_FILE_NAME:
				fnlen = dh_len >= NAME_MAX ? NAME_MAX - 1 : dh_len;
				read_filename(filename, dh_data, fnlen);
				break;
			case HTLC_DATA_FILE_RENAME:
				newfnlen = dh_len >= NAME_MAX ? NAME_MAX - 1 : dh_len;
				read_filename(newfilename, dh_data, newfnlen);
				break;
			case HTLC_DATA_DIR:
				if ((err = hldir_to_path(dh, ROOTDIR, dir, dir))) {
					snd_strerror(htlc, err);
					return;
				}
				break;
			case HTLC_DATA_FILE_COMMENT:
				comlen = dh_len > 255 ? 255 : dh_len;
				memcpy(comment, dh_data, comlen);
				break;
		}
	dh_end()

	if (!fnlen || (!newfnlen && !comlen)) {
		hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, 6, "huh?!?");
		return;
	}

	snprintf(oldbuf, sizeof(oldbuf), "%s/%s", dir[0] ? dir : ROOTDIR, filename);
	if (stat(oldbuf, &sb)) {
		snd_strerror(htlc, errno);
		return;
	}
	if (check_dropbox(htlc, oldbuf)) {
		snd_strerror(htlc, EPERM);
		return;
	}

#if defined(CONFIG_HFS) 
	if (comlen) {
		if (S_ISDIR(sb.st_mode)) {
			if (!htlc->access.comment_folders) {
				snd_strerror(htlc, EPERM);
				return;
			}
		} else {
			if (!htlc->access.comment_files) {
				snd_strerror(htlc, EPERM);
				return;
			}
		}
		if (log_comment)
			hxd_log("%s:%s:%u - comment %s to %.*s", htlc->name, htlc->login, htlc->uid, oldbuf, comlen, comment);
		comment_write(oldbuf, comment, comlen);
	}
#endif

	if (!newfnlen)
		goto ret;

	if (dir[0])
		snprintf(newbuf, sizeof(newbuf), "%s/%s", dir, newfilename);
	else
		snprintf(newbuf, sizeof(newbuf), "%s/%s", ROOTDIR, newfilename);

	if (S_ISDIR(sb.st_mode)) {
		if (!htlc->access.rename_folders) {
			snd_strerror(htlc, EPERM);
			return;
		}
	} else {
		if (!htlc->access.rename_files) {
			snd_strerror(htlc, EPERM);
			return;
		}
	}

	if (log_rename)
		hxd_log("%s:%s:%u - rename %s to %s", htlc->name, htlc->login, htlc->uid, oldbuf, newbuf);

	if (rename(oldbuf, newbuf)) {
		snd_strerror(htlc, errno);
		return;
	}

#if defined(CONFIG_HFS)
	if (hxd_cfg.files.fork == HFS_FORK_CAP) {
		if (!resource_path(rsrcpath_old, oldbuf, &sb)) {
			if ((err = resource_path(rsrcpath_new, newbuf, 0))) {
				/* (void)rename(newbuf, oldbuf); */
				snd_strerror(htlc, err);
				return;
			} else {
				if (rename(rsrcpath_old, rsrcpath_new)) {
					/* (void)rename(newbuf, oldbuf); */
					snd_strerror(htlc, errno);
					return;
				}
			}
		}
	}
	if (!finderinfo_path(rsrcpath_old, oldbuf, &sb)) {
		if ((err = finderinfo_path(rsrcpath_new, newbuf, 0))) {
			/* (void)rename(newbuf, oldbuf); */
			snd_strerror(htlc, err);
			return;
		} else {
			if (rename(rsrcpath_old, rsrcpath_new)) {
				/* (void)rename(newbuf, oldbuf); */
				snd_strerror(htlc, errno);
				return;
			}
		}
	}
#endif /* CONFIG_HFS */

ret:
	hlwrite(htlc, HTLS_HDR_TASK, 0, 0);
}

int
copy_and_unlink (const char *oldpath, const char *newpath)
{
	int rfd, wfd, err;
	ssize_t r;
	char *buf;

	rfd = open(oldpath, O_RDONLY);
	if (rfd < 0)
		return rfd;
	wfd = open(newpath, O_WRONLY|O_CREAT|O_TRUNC, hxd_cfg.permissions.files);
	if (wfd < 0) {
		close(rfd);
		return wfd;
	}
	buf = xmalloc(COPY_BUFSIZE);
	for (;;) {
		r = read(rfd, buf, COPY_BUFSIZE);
		if (r == 0) {
			err = 0;
			break;
		}
		if (r < 0) {
			err = errno;
			break;
		}
		if (write(wfd, buf, r) != r) {
			err = errno;
			break;
		}
	}
	xfree(buf);

	close(rfd);
	close(wfd);

	if (err) {
		errno = err;
		return -1;
	} else
		return unlink(oldpath);
}

void
rcv_file_move (struct htlc_conn *htlc)
{
	u_int16_t fnlen = 0;
	char dir[MAXPATHLEN], newdir[MAXPATHLEN],
	     filename[NAME_MAX], oldbuf[MAXPATHLEN], newbuf[MAXPATHLEN];
	char rsrcpath_old[MAXPATHLEN], rsrcpath_new[MAXPATHLEN];
	struct stat sb, rsb;
	int err;
	dev_t diff_device;

	dir[0] = newdir[0] = 0;

	dh_start(htlc)
		switch (dh_type) {
			case HTLC_DATA_FILE_NAME:
				fnlen = dh_len >= NAME_MAX ? NAME_MAX - 1 : dh_len;
				read_filename(filename, dh_data, fnlen);
				break;
			case HTLC_DATA_DIR:
				if ((err = hldir_to_path(dh, ROOTDIR, dir, dir))) {
					snd_strerror(htlc, err);
					return;
				}
				break;
			case HTLC_DATA_DIR_RENAME:
				if ((err = hldir_to_path(dh, ROOTDIR, newdir, newdir))) {
					snd_strerror(htlc, err);
					return;
				}
				break;
		}
	dh_end()

	if ((!dir[0] && !fnlen) || !newdir[0]) {
		hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, 6, "huh?!?");
		return;
	}
	if (!dir[0])
		strcpy(dir, ROOTDIR);
	if (fnlen) {
		snprintf(oldbuf, sizeof(oldbuf), "%s/%s", dir, filename);
		snprintf(newbuf, sizeof(newbuf), "%s/%s", newdir, filename);
	} else {
		strcpy(oldbuf, dir);
		strcpy(newbuf, newdir);
	}

	if (check_dropbox(htlc, oldbuf) || check_dropbox(htlc, newbuf)) {
		snd_strerror(htlc, EPERM);
		return;
	}

	if (stat(oldbuf, &sb)) {
		snd_strerror(htlc, errno);
		return;
	}
	if (S_ISDIR(sb.st_mode)) {
		if (!htlc->access.move_folders) {
			snd_strerror(htlc, EPERM);
			return;
		}
	} else {
		if (!htlc->access.move_files) {
			snd_strerror(htlc, EPERM);
			return;
		}
	}

	if (log_move)
		hxd_log("%s:%s:%u - move %s to %s", htlc->name, htlc->login, htlc->uid, oldbuf, newbuf);

	diff_device = sb.st_dev;
	if (stat(newdir, &sb)) {
		snd_strerror(htlc, errno);
		return;
	}

#if 0 /* gcc on hpux does not like this */
	diff_device &= ~sb.st_dev;
#else
	diff_device = diff_device != sb.st_dev;
#endif

	if (diff_device ? copy_and_unlink(oldbuf, newbuf) : rename(oldbuf, newbuf)) {
		snd_strerror(htlc, errno);
		return;
	}

#if defined(CONFIG_HFS)
	if (hxd_cfg.files.fork == HFS_FORK_CAP) {
		if (!resource_path(rsrcpath_old, oldbuf, &rsb)) {
			if ((err = resource_path(rsrcpath_new, newbuf, 0))) {
				/* (void)rename(newbuf, oldbuf); */
				snd_strerror(htlc, err);
				return;
			} else {
				if (diff_device ? copy_and_unlink(rsrcpath_old, rsrcpath_new) : rename(rsrcpath_old, rsrcpath_new)) {
					/* (void)rename(newbuf, oldbuf); */
					snd_strerror(htlc, errno);
					return;
				}
			}
		}
	}
	if (!finderinfo_path(rsrcpath_old, oldbuf, &rsb)) {
		if ((err = finderinfo_path(rsrcpath_new, newbuf, 0))) {
			/* (void)rename(newbuf, oldbuf); */
			snd_strerror(htlc, err);
			return;
		} else {
			if (diff_device ? copy_and_unlink(rsrcpath_old, rsrcpath_new) : rename(rsrcpath_old, rsrcpath_new)) {
				/* (void)rename(newbuf, oldbuf); */
				snd_strerror(htlc, errno);
				return;
			}
		}
	}
#endif /* CONFIG_HFS */

	hlwrite(htlc, HTLS_HDR_TASK, 0, 0);
}

void
rcv_file_mkdir (struct htlc_conn *htlc)
{
	u_int16_t fnlen = 0;
	char dir[MAXPATHLEN], filename[NAME_MAX], newbuf[MAXPATHLEN];
	int err;

	dir[0] = 0;

	dh_start(htlc)
		switch (dh_type) {
			case HTLC_DATA_FILE_NAME:
				fnlen = dh_len >= NAME_MAX ? NAME_MAX - 1 : dh_len;
				read_filename(filename, dh_data, fnlen);
				break;
			case HTLC_DATA_DIR:
				err = hldir_to_path(dh, ROOTDIR, dir, dir);
				if (err && err != ENOENT) {
					snd_strerror(htlc, err);
					return;
				}
				break;
		}
	dh_end()

	if (!fnlen && !dir[0]) {
		hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, 6, "huh?!?");
		return;
	}
	if (dir[0]) {
		if (fnlen)
			snprintf(newbuf, sizeof(newbuf), "%s/%s", dir, filename);
		else
			strcpy(newbuf, dir);
	} else {
		snprintf(newbuf, sizeof(newbuf), "%s/%s", ROOTDIR, filename);
	}
	if (check_dropbox(htlc, newbuf)) {
		snd_strerror(htlc, EPERM);
		return;
	}

	if (log_mkdir)
		hxd_log("%s:%s:%u - mkdir %s", htlc->name, htlc->login, htlc->uid, newbuf);

	if (mkdir(newbuf, hxd_cfg.permissions.directories))
		snd_strerror(htlc, errno);
	else
		hlwrite(htlc, HTLS_HDR_TASK, 0, 0);
}

void
rcv_file_symlink (struct htlc_conn *htlc)
{
	u_int16_t fnlen = 0, newfnlen = 0;
	char dir[MAXPATHLEN], newdir[MAXPATHLEN],
	     filename[NAME_MAX], newfilename[NAME_MAX], oldbuf[MAXPATHLEN], newbuf[MAXPATHLEN];
	char rsrcpath_old[MAXPATHLEN], rsrcpath_new[MAXPATHLEN];
	struct stat rsb;
	int err;

	dir[0] = newdir[0] = 0;

	dh_start(htlc)
		switch (dh_type) {
			case HTLC_DATA_FILE_NAME:
				fnlen = dh_len >= NAME_MAX ? NAME_MAX - 1 : dh_len;
				read_filename(filename, dh_data, fnlen);
				break;
			case HTLC_DATA_FILE_RENAME:
				newfnlen = dh_len >= NAME_MAX ? NAME_MAX - 1 : dh_len;
				read_filename(newfilename, dh_data, newfnlen);
				break;
			case HTLC_DATA_DIR:
				if ((err = hldir_to_path(dh, ROOTDIR, dir, dir))) {
					snd_strerror(htlc, err);
					return;
				}
				break;
			case HTLC_DATA_DIR_RENAME:
				if ((err = hldir_to_path(dh, ROOTDIR, newdir, newdir))) {
					snd_strerror(htlc, err);
					return;
				}
				break;
		}
	dh_end()

	if ((!dir[0] && !fnlen) || !newdir[0]) {
		hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, 6, "huh?!?");
		return;
	}
	if (!dir[0])
		strcpy(dir, ROOTDIR);
	if (fnlen) {
		snprintf(oldbuf, sizeof(oldbuf), "%s/%s", dir, filename);
		snprintf(newbuf, sizeof(newbuf), "%s/%s", newdir, newfnlen ? newfilename : filename);
	} else {
		strcpy(oldbuf, dir);
		strcpy(newbuf, newdir);
	}
	if (check_dropbox(htlc, oldbuf)) {
		snd_strerror(htlc, EPERM);
		return;
	}

	if (log_symlink)
		hxd_log("%s:%s:%u - symlink %s to %s", htlc->name, htlc->login, htlc->uid, newbuf, oldbuf);

	if (symlink(oldbuf, newbuf))
		snd_strerror(htlc, errno);
	else
		hlwrite(htlc, HTLS_HDR_TASK, 0, 0);
#if defined(CONFIG_HFS)
	if (hxd_cfg.files.fork == HFS_FORK_CAP) {
		if (!resource_path(rsrcpath_old, oldbuf, &rsb)) {
			if ((err = resource_path(rsrcpath_new, newbuf, 0))) {
				/* (void)unlink(newbuf); */
				snd_strerror(htlc, err);
				return;
			} else {
				if (symlink(rsrcpath_old, rsrcpath_new)) {
					/* (void)unlink(newbuf); */
					snd_strerror(htlc, errno);
					return;
				}
			}
		}
	}
	if (!finderinfo_path(rsrcpath_old, oldbuf, &rsb)) {
		if ((err = finderinfo_path(rsrcpath_new, newbuf, 0))) {
			/* (void)unlink(newbuf); */
			snd_strerror(htlc, err);
			return;
		} else {
			if (symlink(rsrcpath_old, rsrcpath_new)) {
				/* (void)unlink(newbuf); */
				snd_strerror(htlc, errno);
				return;
			}
		}
	}
#endif /* CONFIG_HFS */
}

static int
recursive_rmdir (char *dirpath)
{
	DIR *dir;
	struct dirent *de;
	char pathbuf[MAXPATHLEN];
	struct stat sb;
	int err;

	dir = opendir(dirpath);
	if (!dir)
		return 1;
	while ((de = readdir(dir))) {
		if (de->d_name[0] == '.' && ((de->d_name[1] == '.' && !de->d_name[2]) || !de->d_name[1]))
			continue;
		snprintf(pathbuf, MAXPATHLEN, "%s/%s", dirpath, de->d_name);
		if ((err = lstat(pathbuf, &sb)))
			goto ret;
		if (S_ISDIR(sb.st_mode) && !S_ISLNK(sb.st_mode))
			err = recursive_rmdir(pathbuf);
		else
			err = unlink(pathbuf);
		if (err)
			goto ret;
	}
	closedir(dir);
	return rmdir(dirpath);
ret:
	closedir(dir);

	return err;
}

void
rcv_file_delete (struct htlc_conn *htlc)
{
	u_int16_t fnlen = 0;
	char dir[MAXPATHLEN], filename[NAME_MAX], oldbuf[MAXPATHLEN];
	char rsrcpath_old[MAXPATHLEN];
	struct stat sb, rsb;
	int err;

	dir[0] = 0;

	dh_start(htlc)
		switch (dh_type) {
			case HTLC_DATA_FILE_NAME:
				fnlen = dh_len >= NAME_MAX ? NAME_MAX - 1 : dh_len;
				read_filename(filename, dh_data, fnlen);
				break;
			case HTLC_DATA_DIR:
				if ((err = hldir_to_path(dh, ROOTDIR, dir, dir))) {
					snd_strerror(htlc, err);
					return;
				}
				break;
		}
	dh_end()

	if (!fnlen && !dir[0]) {
		hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, 6, "huh?!?");
		return;
	}

	if (dir[0]) {
		if (fnlen)
			snprintf(oldbuf, sizeof(oldbuf), "%s/%s", dir, filename);
		else
			strcpy(oldbuf, dir);
	} else {
		snprintf(oldbuf, sizeof(oldbuf), "%s/%s", ROOTDIR, filename);
	}
	if (check_dropbox(htlc, oldbuf)) {
		snd_strerror(htlc, EPERM);
		return;
	}

	if (log_delete)
		hxd_log("%s:%s:%u - delete %s", htlc->name, htlc->login, htlc->uid, oldbuf);

	if (lstat(oldbuf, &sb)) {
		snd_strerror(htlc, errno);
		return;
	}

#if defined(CONFIG_HFS)
	if (hxd_cfg.files.fork == HFS_FORK_CAP) {
		if (!S_ISDIR(sb.st_mode) && !resource_path(rsrcpath_old, oldbuf, &rsb)
		    && !S_ISDIR(rsb.st_mode)) {
			if (unlink(rsrcpath_old)) {
				snd_strerror(htlc, errno);
				return;
			}
		}
	}
	if (!finderinfo_path(rsrcpath_old, oldbuf, &rsb)) {
		if (unlink(rsrcpath_old)) {
			snd_strerror(htlc, errno);
			return;
		}
	}
#endif /* CONFIG_HFS */

	if (S_ISDIR(sb.st_mode) && !S_ISLNK(sb.st_mode))
		err = recursive_rmdir(oldbuf);
	else
		err = unlink(oldbuf);

	if (err)
		snd_strerror(htlc, errno);
	else
		hlwrite(htlc, HTLS_HDR_TASK, 0, 0);
}

void
rcv_file_getinfo (struct htlc_conn *htlc)
{
	u_int32_t size;
	u_int8_t date_create[8], date_modify[8];
	u_int16_t fnlen = 0;
	char dir[MAXPATHLEN], filename[NAME_MAX], oldbuf[MAXPATHLEN];
	struct stat sb;
	int is_link;
	int err;
	u_int16_t file_typelen, file_creatorlen;
	u_int8_t file_type[12], file_creator[4];
	u_int32_t mactime;
#if defined(CONFIG_HFS)
	struct hfsinfo fi;
#endif

	dir[0] = 0;

	dh_start(htlc)
		switch (dh_type) {
			case HTLC_DATA_FILE_NAME:
				fnlen = dh_len > NAME_MAX ? NAME_MAX - 1 : dh_len;
				read_filename(filename, dh_data, fnlen);
				break;
			case HTLC_DATA_DIR:
				if ((err = hldir_to_path(dh, ROOTDIR, dir, dir))) {
					snd_strerror(htlc, err);
					return;
				}
				break;
		}
	dh_end()

	if (!fnlen && !dir[0]) {
		hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, 6, "huh?!?");
		return;
	}

	if (dir[0]) {
		if (fnlen)
			snprintf(oldbuf, sizeof(oldbuf), "%s/%s", dir, filename);
		else {
			int i, len = strlen(dir);

			for (i = len - 1; i > 0; i--)
				if (dir[i] == DIRCHAR) {
					fnlen = len - i > NAME_MAX ? NAME_MAX : len - i;
					strcpy(filename, &dir[len - fnlen + 1]);
					break;
				}
			strcpy(oldbuf, dir);
		}
	} else {
		snprintf(oldbuf, sizeof(oldbuf), "%s/%s", ROOTDIR, filename);
	}
	if (check_dropbox(htlc, oldbuf)) {
		snd_strerror(htlc, EPERM);
		return;
	}

#if 0
	{
		char *p;
		for (p = oldbuf+strlen(ROOTDIR); *p; p++)
			if ((*p != '.' && *p != '/') || (p-2 >= oldbuf && *p == '.' && *(p-1) == '.' && *(p-2) == '.'))
				goto ok;
		snd_strerror(htlc, EPERM);
		return;
	}

ok:
#endif
	if (log_getinfo)
		hxd_log("%s:%s:%u - getinfo %s", htlc->name, htlc->login, htlc->uid, oldbuf);

	if (lstat(oldbuf, &sb)) {
fark:		snd_strerror(htlc, errno);
		return;
	}
	if (S_ISLNK(sb.st_mode)) {
		is_link = 1;
		if (stat(oldbuf, &sb))
			goto fark;
	} else {
		is_link = 0;
	}
	size = sb.st_size;
#if defined(CONFIG_HFS)
	size += resource_len(oldbuf);
#endif
	size = htonl(size);
	memset(date_create, 0, 8);
	memset(date_modify, 0, 8);

#if defined(CONFIG_HFS)
	hfsinfo_read(oldbuf, &fi);
	mactime = hfs_h_to_mtime(fi.create_time);
	*((u_int16_t *)date_create) = htons(1904);
	*((u_int32_t *)(date_create+4)) = mactime;
	mactime = hfs_h_to_mtime(fi.modify_time);
	*((u_int16_t *)date_modify) = htons(1904);
	*((u_int32_t *)(date_modify+4)) = mactime;
	file_typelen = 4;
	file_creatorlen = 4;
	if (S_ISDIR(sb.st_mode)) {
		if (is_link) {
			file_typelen = 12;
			memcpy(file_type, "Folder Alias", file_typelen);
		} else
			memcpy(file_type, "fldr", 4);
		memcpy(fi.type, "fldr", 4);
		memcpy(file_creator, "n/a ", 4);
	} else {
		memcpy(file_type, fi.type, 4);
		memcpy(file_creator, fi.creator, 4);
	}

	hlwrite(htlc, HTLS_HDR_TASK, 0, 8,
		HTLS_DATA_FILE_ICON, 4, fi.type,
		HTLS_DATA_FILE_TYPE, file_typelen, file_type,
		HTLS_DATA_FILE_CREATOR, file_creatorlen, file_creator,
		HTLS_DATA_FILE_SIZE, sizeof(size), &size,
		HTLS_DATA_FILE_NAME, fnlen, filename,
		HTLS_DATA_FILE_DATE_CREATE, 8, date_create,
		HTLS_DATA_FILE_DATE_MODIFY, 8, date_modify,
		HTLS_DATA_FILE_COMMENT, fi.comlen > 200 ? 200 : fi.comlen, fi.comment);
#else
	mactime = htonl(sb.st_mtime + 2082844800);
	*((u_int16_t *)date_modify) = 1904;
	*((u_int32_t *)(date_modify+4)) = mactime;
	hlwrite(htlc, HTLS_HDR_TASK, 0, 3,
		HTLS_DATA_FILE_SIZE, sizeof(size), &size,
		HTLS_DATA_FILE_NAME, fnlen, filename,
		HTLS_DATA_FILE_DATE_MODIFY, 8, date_modify);
#endif
}

#ifdef CONFIG_HOPE
void
rcv_file_hash (struct htlc_conn *htlc)
{
	u_int16_t fnlen = 0;
	char dir[MAXPATHLEN], filename[NAME_MAX], pathbuf[MAXPATHLEN];
	int err;
	int fd;
	u_int32_t data_len = 0, rsrc_len = 0;
	u_int16_t haval_len = 16, haval_passes = 3, hash_types = 0;
	u_int8_t md5[32], haval[64], sha1[40];
#if defined(CONFIG_HFS)
	int rfd;
	off_t off;
#endif

	dir[0] = 0;

	dh_start(htlc)
		switch (dh_type) {
			case HTLC_DATA_FILE_NAME:
				fnlen = dh_len > NAME_MAX ? NAME_MAX - 1 : dh_len;
				read_filename(filename, dh_data, fnlen);
				break;
			case HTLC_DATA_DIR:
				if ((err = hldir_to_path(dh, ROOTDIR, dir, dir))) {
					snd_strerror(htlc, err);
					return;
				}
				break;
			case HTLC_DATA_RFLT:
				if (dh_len >= 66) {
					L32NTOH(data_len, &dh_data[46]);
					L32NTOH(rsrc_len, &dh_data[62]);
				}
				break;
			case HTLC_DATA_HASH_MD5:
				hash_types |= 0x01;
				break;
			case HTLC_DATA_HASH_HAVAL:
				hash_types |= 0x02;
				if (dh_len == 2) {
					haval_len = dh_data[0];
					haval_passes = dh_data[1];
				}
				if (haval_len > 32)
					haval_len = 32;
				if (haval_passes < 3)
					haval_passes = 3;
				if (haval_passes > 5)
					haval_passes = 5;
				break;
			case HTLC_DATA_HASH_SHA1:
				hash_types |= 0x04;
				break;
		}
	dh_end()

	if (!fnlen && !dir[0]) {
		hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, 6, "huh?!?");
		return;
	}
	if (dir[0]) {
		if (fnlen)
			snprintf(pathbuf, sizeof(pathbuf), "%s/%s", dir, filename);
		else
			strcpy(pathbuf, dir);
	} else {
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", ROOTDIR, filename);
	}
	if (check_dropbox(htlc, pathbuf)) {
		snd_strerror(htlc, EPERM);
		return;
	}

	if (log_hash)
		hxd_log("%s:%s:%u - hash %s", htlc->name, htlc->login, htlc->uid, pathbuf);

	fd = open(pathbuf, O_RDONLY);
	if (fd < 0) {
		snd_strerror(htlc, errno);
		return;
	}
#if defined(CONFIG_HFS)
	rfd = resource_open(pathbuf, O_RDONLY, 0);
	off = lseek(rfd, 0, SEEK_CUR);
	if (off == (off_t)-1) {
		if (rfd >= 0)
			close(rfd);
		rfd = -1;
	}
#endif
	if (hash_types & 0x01) {
		memset(md5, 0, 32);
		md5_fd(fd, data_len, &md5[0]);
#if defined(CONFIG_HFS)
		if (rfd >= 0)
			md5_fd(rfd, rsrc_len, &md5[16]);
#endif
	}
	if (hash_types & 0x02) {
		memset(haval, 0, haval_len * 2);
		lseek(fd, 0, SEEK_SET);
		haval_fd(fd, data_len, &haval[0], haval_len * 8, haval_passes);
#if defined(CONFIG_HFS)
		if (rfd >= 0) {
			lseek(rfd, off, SEEK_SET);
			haval_fd(rfd, rsrc_len, &haval[haval_len], haval_len * 8, haval_passes);
		}
#endif
	}
	if (hash_types & 0x04) {
		memset(sha1, 0, 40);
		lseek(fd, 0, SEEK_SET);
		sha_fd(fd, data_len, &sha1[0]);
#if defined(CONFIG_HFS)
		if (rfd >= 0) {
			lseek(rfd, off, SEEK_SET);
			sha_fd(rfd, rsrc_len, &sha1[20]);
		}
#endif
	}
#if defined(CONFIG_HFS)
	if (rfd >= 0)
		close(rfd);
#endif
	close(fd);

#if defined(CONFIG_HFS)
	hlwrite(htlc, HTLS_HDR_TASK, 0, 3,
		HTLS_DATA_HASH_MD5, 32, md5,
		HTLS_DATA_HASH_HAVAL, haval_len * 2, haval,
		HTLS_DATA_HASH_SHA1, 40, sha1);
#else
	hlwrite(htlc, HTLS_HDR_TASK, 0, 3,
		HTLS_DATA_HASH_MD5, 16, md5,
		HTLS_DATA_HASH_HAVAL, haval_len, haval,
		HTLS_DATA_HASH_SHA1, 20, sha1);
#endif
}
#endif

#if defined(CONFIG_HTXF_QUEUE)
u_int16_t
insert_into_queue(void)
{
	if (nr_queued || (nr_gets >= hxd_cfg.limits.total_downloads)) {
		hxd_log("Inserting into queue at #%d. nr_gets=%d, limit=%d, queue limit=%d",
			nr_queued+1, nr_gets, hxd_cfg.limits.total_downloads, hxd_cfg.limits.queue_size);
		return ++nr_queued;
	} else
		return 0;
}
#endif

void
rcv_file_get (struct htlc_conn *htlc)
{
	u_int16_t fnlen = 0, preview = 0;
	char path[MAXPATHLEN], dir[MAXPATHLEN], filename[NAME_MAX];
	char abuf[16];
	struct stat sb;
	u_int32_t size = 0, data_size = 0, rsrc_size = 0, ref, 
		  data_pos = 0, rsrc_pos = 0;
	int err;
	int siz;
	struct htxf_conn *htxf;
	u_int16_t i;
#if defined(CONFIG_HTXF_QUEUE)
	u_int16_t queue_pos;
#endif

	dir[0] = 0;

#if !defined(CONFIG_HTXF_CLONE)
	if (htlc->nr_gets >= htlc->get_limit) {
		snprintf(abuf, 13, "%u at a time", htlc->get_limit);
		hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, 13, abuf);
		return;
	}
#endif
#if defined(CONFIG_HTXF_QUEUE)
	if (nr_queued >= hxd_cfg.limits.queue_size) {
#else
	if (nr_gets >= hxd_cfg.limits.total_downloads) {
#endif
		char buf[128];
#if defined(CONFIG_HTXF_QUEUE)
		int len = snprintf(buf, sizeof(buf), "Server's queue is full (%u >= %ld) please try again later",
			nr_gets, hxd_cfg.limits.queue_size);
#else
		int len = snprintf(buf, sizeof(buf), "maximum number of total downloads reached (%u >= %ld)",
				   nr_gets, hxd_cfg.limits.total_downloads);
#endif
		hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, len, buf);
		return;
	}
	for (i = 0; i < HTXF_GET_MAX; i++)
		if (!htlc->htxf_out[i])
			break;
	if (i == HTXF_GET_MAX) {
		snd_strerror(htlc, EAGAIN);
		return;
	}

	dh_start(htlc)
		switch (dh_type) {
			case HTLC_DATA_FILE_NAME:
				fnlen = dh_len >= NAME_MAX ? NAME_MAX - 1 : dh_len;
				read_filename(filename, dh_data, fnlen);
				break;
			case HTLC_DATA_DIR:
				if ((err = hldir_to_path(dh, ROOTDIR, dir, dir))) {
					snd_strerror(htlc, err);
					return;
				}
				break;
			case HTLC_DATA_RFLT:
				if (dh_len >= 50)
					L32NTOH(data_pos, &dh_data[46]);
				if (dh_len >= 66)
					L32NTOH(rsrc_pos, &dh_data[62]);
				break;
			case HTLC_DATA_FILE_PREVIEW:
				if (dh_len >= 2)
					L16NTOH(preview, dh_data);
				break;
		}
	dh_end()
	if (!fnlen && !dir[0]) {
		hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, 6, "huh?!?");
		return;
	}

	if (dir[0]) {
		if (fnlen)
			snprintf(path, sizeof(path), "%s/%s", dir, filename);
		else
			strcpy(path, dir);
	} else {
		snprintf(path, sizeof(path), "%s/%s", ROOTDIR, filename);
	}
	if (check_dropbox(htlc, path)) {
		snd_strerror(htlc, EPERM);
		return;
	}

#ifdef CONFIG_HTXF_PREVIEW
	if (preview) {
		Image *img, *mimg;
		ImageInfo ii;

#if MaxTextExtent < MAXPATHLEN
		if (strlen(path) >= sizeof(ii.filename)) {
			hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, 13, "path too long");
			return;
		}
#endif
		GetImageInfo(&ii);
		strcpy(ii.filename, path);
		img = ReadImage(&ii);
		if (!img)
			goto text_preview;
		mimg = MinifyImage(img);
		DestroyImage(img);
		if (!mimg) {
			hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, 18, "MinifyImage failed");
			return;
		}
		if ((err = preview_path(path, path, 0))) {
			snd_strerror(htlc, err);
			DestroyImage(mimg);
			return;
		}
		strcpy(mimg->filename, path);
		data_pos = 0;
		rsrc_pos = 0;
		WriteImage(&ii, mimg);
		DestroyImage(mimg);
	}

text_preview:
#endif
	if (stat(path, &sb)) {
		snd_strerror(htlc, errno);
		return;
	}

	if (S_ISDIR(sb.st_mode)) {
		snd_strerror(htlc, EISDIR);
		return;
	}

	data_size = sb.st_size;
#if defined(CONFIG_HFS)
	rsrc_size = resource_len(path);
	size = (data_size - data_pos) + (preview ? 0 : (rsrc_size - rsrc_pos));
	if (!preview)
		size += 133 + ((rsrc_size - rsrc_pos) ? 16 : 0) + comment_len(path);
#else
	size = (data_size - data_pos) + (preview ? 0 : 133);
#endif

	/* XXX */
#ifdef CONFIG_IPV6
	ref = (htlc->sockaddr.SIN_ADDR.s6_addr32); /* ref is a 32-bit value */ 
#else
	ref = (htlc->sockaddr.SIN_ADDR.S_ADDR);
#endif

	ref *= ref;
	ref *= (htlc->sockaddr.SIN_PORT * htlc->trans);
	ref *= ref;
	ref = htonl(ref);

	htxf = xmalloc(sizeof(struct htxf_conn));
	memset(htxf, 0, sizeof(struct htxf_conn));
	htxf->data_size = data_size;
	htxf->rsrc_size = rsrc_size;
	htxf->data_pos = data_pos;
	htxf->rsrc_pos = rsrc_pos;
	htxf->total_pos = 0;
	htxf->gone = 0;
	htxf->ref = ref;
	htxf->preview = preview;
	htxf->sockaddr = htlc->sockaddr;
#if defined(CONFIG_HTXF_PTHREAD) || defined(CONFIG_HTXF_CLONE) || defined(CONFIG_HTXF_FORK)
	siz = sizeof(struct SOCKADDR_IN);
	if (getsockname(htlc->fd, (struct SOCKADDR *)&htxf->listen_sockaddr, &siz)) {
		hxd_log("rcv_file_get: getsockname: %s", strerror(errno));
		snd_strerror(htlc, errno);
		xfree(htxf);
		return;
	}
	htxf->listen_sockaddr.SIN_PORT = htons(ntohs(htxf->listen_sockaddr.SIN_PORT) + 1);
#endif
	strcpy(htxf->path, path);
	htxf->htlc = htlc;

	LOCK_HTXF(htlc);
	for (i = 0; i < HTXF_GET_MAX; i++) {
		if (!htlc->htxf_out[i]) {
			htlc->htxf_out[i] = htxf;
			break;
		}
	}
	UNLOCK_HTXF(htlc);
#if defined(CONFIG_HTXF_QUEUE)
	if (htlc->can_download)
		htxf->queue_pos = queue_pos = 0;
	else
		htxf->queue_pos = queue_pos = insert_into_queue();
#endif
	
	htlc->nr_gets++;
	nr_gets++;
#if HTXF_THREADS_LISTEN
	err = htxf_thread_create(get_thread, htxf);
	if (err) {
		LOCK_HTXF(htlc);
		for (i = 0; i < HTXF_GET_MAX; i++) {
			if (htlc->htxf_out[i] == htxf) {
				htlc->htxf_out[i] = 0;
				break;
			}
		}
		UNLOCK_HTXF(htlc);
		htlc->nr_gets--;
		nr_gets--;
		xfree(htxf);
		snd_strerror(htlc, err);
		return;
	}
#endif /* htxf threads listen */
	if (log_download) {
#ifdef CONFIG_IPV6
		inet_ntop(AFINET, (char *)&htlc->sockaddr.SIN_ADDR, abuf, sizeof(abuf));
#else
		inet_ntoa_r(htlc->sockaddr.SIN_ADDR, abuf, sizeof(abuf));
#endif
		hxd_log("%s@%s:%u - %s:%u:%u:%s - download %s:%08x", htlc->userid, abuf, ntohs(htlc->sockaddr.SIN_PORT),
			htlc->name, htlc->icon, htlc->uid, htlc->login, htxf->path, htxf->ref);
	}
	size = htonl(size);
#if defined(CONFIG_HTXF_QUEUE)
	queue_pos = htons(queue_pos);
	hlwrite(htlc, HTLS_HDR_TASK, 0, 3,
		HTLS_DATA_HTXF_REF, sizeof(ref), &ref,
		HTLS_DATA_HTXF_SIZE, sizeof(size), &size,
		HTLS_DATA_QUEUE_UPDATE, sizeof(queue_pos), &queue_pos);
#else
	hlwrite(htlc, HTLS_HDR_TASK, 0, 2,
		HTLS_DATA_HTXF_REF, sizeof(ref), &ref,
		HTLS_DATA_HTXF_SIZE, sizeof(size), &size);
#endif
}

void
rcv_file_put (struct htlc_conn *htlc)
{
	u_int16_t fnlen = 0, resume = 0;
	char path[MAXPATHLEN], dir[MAXPATHLEN], filename[NAME_MAX];
#ifdef CONFIG_IPV6
	char abuf[HOSTLEN+1];
#else
	char abuf[16];
#endif
	struct stat sb;
	int err;
	int siz;
	u_int32_t ref, data_pos = 0, rsrc_pos = 0;
	u_int8_t rflt[74];
	struct htxf_conn *htxf;
	u_int16_t i;

	dir[0] = 0;

	if (htlc->nr_puts >= htlc->put_limit) {
		snprintf(abuf, 13, "%u at a time", htlc->put_limit);
		hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, 13, abuf);
		return;
	}
	if (nr_puts >= hxd_cfg.limits.total_uploads) {
		char buf[128];
		int len = snprintf(buf, sizeof(buf), "maximum number of total uploads reached (%u >= %ld)",
				   nr_gets, hxd_cfg.limits.total_uploads);
		hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, len, buf);
		return;
	}
	for (i = 0; i < HTXF_PUT_MAX; i++)
		if (!htlc->htxf_in[i])
			break;
	if (i == HTXF_PUT_MAX) {
		snd_strerror(htlc, EAGAIN);
		return;
	}

	dh_start(htlc)
		switch (dh_type) {
			case HTLC_DATA_FILE_NAME:
				fnlen = dh_len >= NAME_MAX ? NAME_MAX - 1 : dh_len;
				read_filename(filename, dh_data, fnlen);
				break;
			case HTLC_DATA_DIR:
				if ((err = hldir_to_path(dh, ROOTDIR, dir, dir))) {
					snd_strerror(htlc, err);
					return;
				}
				break;
			case HTLC_DATA_FILE_PREVIEW:
				if (dh_len >= 2)
					L16NTOH(resume, dh_data);
				break;
		}
	dh_end()

	if (!htlc->access.upload_anywhere && (!dir[0] || (!strcasestr(dir, "UPLOAD") && !strcasestr(dir, "DROP BOX")))) {
		snd_strerror(htlc, EPERM);
		return;
	}
	if (!fnlen && !dir[0]) {
		hlwrite(htlc, HTLS_HDR_TASK, 1, 1, HTLS_DATA_TASKERROR, 6, "huh?!?");
		return;
	}

	if (dir[0]) {
		if (fnlen)
			snprintf(path, sizeof(path), "%s/%s", dir, filename);
		else
			strcpy(path, dir);
	} else {
		snprintf(path, sizeof(path), "%s/%s", ROOTDIR, filename);
	}

	if (!resume) {
		if (!stat(path, &sb)) {
			snd_strerror(htlc, EEXIST);
			return;
		}
		if (errno != ENOENT) {
			snd_strerror(htlc, errno);
			return;
		}
	} else {
		if (stat(path, &sb)) {
			snd_strerror(htlc, errno);
			return;
		}
		data_pos = sb.st_size;
#if defined(CONFIG_HFS)
		rsrc_pos = resource_len(path);
#endif
		memcpy(rflt, "RFLT\0\1\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\2DATA\0\0\0\0\0\0\0\0\0\0\0\0MACR\0\0\0\0\0\0\0\0\0\0\0\0", 74);
		S32HTON(data_pos, &rflt[46]);
		S32HTON(rsrc_pos, &rflt[62]);
	}

#ifdef CONFIG_IPV6
	ref = htlc->sockaddr.SIN_ADDR.s6_addr32; /* ref is a 32-bit value */
#else
	ref = htlc->sockaddr.SIN_ADDR.S_ADDR;
#endif
	ref *= ref;
	ref *= (htlc->sockaddr.SIN_PORT * htlc->trans);
	ref *= ref;
	ref = htonl(ref);

	htxf = xmalloc(sizeof(struct htxf_conn));
	memset(htxf, 0, sizeof(struct htxf_conn));
	htxf->rsrc_size = 0;
	htxf->data_size = 0;
	htxf->data_pos = data_pos;
	htxf->rsrc_pos = rsrc_pos;
	htxf->total_pos = 0;
	htxf->total_size = 0;
	htxf->gone = 0;
	htxf->ref = ref;
	htxf->sockaddr = htlc->sockaddr;
#if defined(CONFIG_HTXF_PTHREAD) || defined(CONFIG_HTXF_CLONE) || defined(CONFIG_HTXF_FORK)
	siz = sizeof(struct SOCKADDR_IN);
	if (getsockname(htlc->fd, (struct SOCKADDR *)&htxf->listen_sockaddr, &siz)) {
		hxd_log("rcv_file_get: getsockname: %s", strerror(errno));
		snd_strerror(htlc, errno);
		xfree(htxf);
		return;
	}
	htxf->listen_sockaddr.SIN_PORT = htons(ntohs(htxf->listen_sockaddr.SIN_PORT) + 1);
#endif
	strcpy(htxf->path, path);
	htxf->htlc = htlc;

	LOCK_HTXF(htlc);
	for (i = 0; i < HTXF_PUT_MAX; i++) {
		if (!htlc->htxf_in[i]) {
			htlc->htxf_in[i] = htxf;
			break;
		}
	}
	UNLOCK_HTXF(htlc);
	htlc->nr_puts++;
	nr_puts++;
#if HTXF_THREADS_LISTEN
	err = htxf_thread_create(put_thread, htxf);
	if (err) {
		LOCK_HTXF(htlc);
		for (i = 0; i < HTXF_PUT_MAX; i++) {
			if (htlc->htxf_in[i] == htxf) {
				htlc->htxf_in[i] = 0;
				break;
			}
		}
		UNLOCK_HTXF(htlc);
		htlc->nr_puts--;
		nr_puts--;
		xfree(htxf);
		snd_strerror(htlc, err);
		return;
	}
#endif /* htxf threads listen */
	if (log_upload) {
#ifdef CONFIG_IPV6
		inet_ntop(AFINET, (char *)&htlc->sockaddr.SIN_ADDR, abuf, sizeof(abuf));
#else
		inet_ntoa_r(htlc->sockaddr.SIN_ADDR, abuf, sizeof(abuf));
#endif
		hxd_log("%s@%s:%u - %s:%u:%u:%s - upload %s:%08x", htlc->userid, abuf, ntohs(htlc->sockaddr.SIN_PORT),
			htlc->name, htlc->icon, htlc->uid, htlc->login, htxf->path, htxf->ref);
	}
	if (!resume)
		hlwrite(htlc, HTLS_HDR_TASK, 0, 1,
			HTLS_DATA_HTXF_REF, sizeof(ref), &ref);
	else
		hlwrite(htlc, HTLS_HDR_TASK, 0, 2,
			HTLS_DATA_RFLT, 74, rflt,
			HTLS_DATA_HTXF_REF, sizeof(ref), &ref);
}
