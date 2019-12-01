#define _XOPEN_SOURCE 500
#include <ctype.h>
#include <stdarg.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <ftw.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/time.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <archive.h>
#include <archive_entry.h>


struct archive *a;
struct archive_entry *entry;

int compress(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
    if(tflag != FTW_D && tflag != FTW_DNR && tflag != FTW_DP)
    {
    char buff[8192];
    entry = archive_entry_new(); // Note 2
    printf("%s\n", fpath);
    printf("%d\n", tflag);
    archive_entry_set_pathname(entry, fpath);
    archive_entry_set_size(entry, sb->st_size); // Note 3
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, sb->st_mode);
    archive_write_header(a, entry);
    int fd = open(fpath, O_RDONLY);
    int len = read(fd, buff, sizeof(buff));
    while ( len > 0 ) {
        archive_write_data(a, buff, len);
        len = read(fd, buff, sizeof(buff));
    }
    close(fd);
    archive_entry_free(entry);
    }
    return 0;
}

int main()
{
    char absolute_path[4096] = {0};
    realpath("./src/", absolute_path);
    char absolute_path_tar[4096] = {0};
    realpath("./compressed.tar", absolute_path_tar);
    a = archive_write_new();
    archive_write_add_filter_gzip(a);
    archive_write_set_format_pax_restricted(a); // Note 1
    archive_write_open_filename(a, absolute_path_tar);
    nftw(absolute_path, compress, 20, 0);
    archive_write_close(a);
    archive_write_free(a);
    return 0;
}
