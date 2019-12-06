/**
 * zlib frontend from libtar
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <libtar.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <zlib.h>

static gzFile *gzfiles = NULL;
static int gzfiles_tail = -1;

static int
gzopen_frontend(char *pathname, int oflags, int mode)
{
	char *gzoflags;
	int fd;
	gzFile *gzfs = gzfiles;

	switch (oflags & O_ACCMODE) {
	case O_WRONLY:
		gzoflags = "wb";
		break;
	case O_RDONLY:
		gzoflags = "rb";
		break;
	default:
	case O_RDWR:
		errno = EINVAL;
		return -1;
	}

	fd = open(pathname, oflags, mode);
	if (fd == -1)
		return -1;

	if ((oflags & O_CREAT) && fchmod(fd, mode)) {
		close(fd);
		return -1;
	}

	if (fd > gzfiles_tail) {
		gzfs = reallocarray(gzfiles, fd + 1, sizeof(gzFile));
		if (gzfs == NULL) {
			errno = ENOMEM;
			return -1;
		}
		gzfiles_tail = fd;
		gzfiles = gzfs;
	}
	gzfs[fd] = gzdopen(fd, gzoflags);
	if (gzfs[fd] == NULL) {
		errno = ENOMEM;
		return -1;
	}
	return fd;
}

static int
gzclose_frontend(int fd)
{
	int ret = gzclose(gzfiles[fd]);
	gzfiles[fd] = NULL;
	for (int i = 0; i < gzfiles_tail; ++i) {
		if (gzfiles[i] != NULL)
			fd = i;
	}

	gzFile *gzfs = reallocarray(gzfiles, fd + 1, sizeof(gzFile));
	if (gzfs == NULL) {
		errno = ENOMEM;
		return -1;
	}
	gzfiles_tail = fd;
	gzfiles = gzfs;
	return ret;
}

static ssize_t
gzread_frontend(int fd, void *buf, size_t count)
{
	return gzread(gzfiles[fd], buf, count);
}

static ssize_t
gzwrite_frontend(int fd, const void *buf, size_t count)
{
	return gzwrite(gzfiles[fd], (void *)buf, count);
}

tartype_t gztype = { (openfunc_t)gzopen_frontend, gzclose_frontend, gzread_frontend, gzwrite_frontend };
