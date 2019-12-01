#include <ctype.h>
#include <stdarg.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
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
#include "cloudapi.h"
#include "cloudfs.h"
#include "dedup.h"

#define UNUSED __attribute__((unused))

static struct cloudfs_state state_;
static FILE *outfile;
static FILE *infile;
static int bucket_found = 0;
static FILE *logfile;
static table_entry *hashes = NULL;
static char *bucket_to_find;
int bytes_read_from_cloud = 0;
void get_full_path(char *fpath, const char *path)
{
  if (!strncmp(path, state_.ssd_path, strlen(state_.ssd_path)))
    strncat(fpath, path, MAX_PATH_LEN - 1);
  else if (!strncmp(path, state_.fuse_path, strlen(state_.fuse_path)))
  {
    if (state_.ssd_path[strlen(state_.ssd_path) - 1] == '/' && path[strlen(state_.fuse_path)] == '/')
      strncpy(fpath, state_.ssd_path, strlen(state_.ssd_path) - 1);
    else
      strncpy(fpath, state_.ssd_path, strlen(state_.ssd_path));
    strncat(fpath, path + strlen(state_.fuse_path), MAX_PATH_LEN - strlen(state_.ssd_path));
  }
  else
  {
    if (state_.ssd_path[strlen(state_.ssd_path) - 1] == '/' && path[0] == '/')
      strncpy(fpath, state_.ssd_path, strlen(state_.ssd_path) - 1);
    else
      strncpy(fpath, state_.ssd_path, strlen(state_.ssd_path));
    strncat(fpath, path, MAX_PATH_LEN - strlen(state_.ssd_path));
  }
}

void log_msg(const char *format, ...)
{
  va_list ap;
  va_start(ap, format);

  vfprintf(logfile, format, ap);
}

int get_buffer(const char *buffer, int bufferLength)
{
  int result =  fwrite(buffer, 1, bufferLength, outfile);
  bytes_read_from_cloud += result;
  log_msg("read %d bytes from cloud\n", bytes_read_from_cloud);
  return result;
}

void get_from_cloud(unsigned char *md5)
{
  char md5_hex[2 * MD5_DIGEST_LENGTH + 1] = {0};
  int i = 0;
  for (i = 0; i < MD5_DIGEST_LENGTH; i++)
  {
    sprintf(&md5_hex[i * 2], "%02x", md5[i]);
  }
  S3Status statusG = cloud_get_object("hashes", md5_hex, get_buffer);
  if (statusG != S3StatusOK)
    log_msg("cloud_get: Status is %s\n", S3_get_status_name(statusG));
}

int put_buffer(char *buffer, int bufferLength)
{
  return fread(buffer, 1, bufferLength, infile);
}

void put_to_cloud(unsigned char *md5, int segment_len)
{
  char md5_hex[2 * MD5_DIGEST_LENGTH + 1] = {0};
  int i = 0;
  for (i = 0; i < MD5_DIGEST_LENGTH; i++)
  {
    sprintf(&md5_hex[i * 2], "%02x", md5[i]);
  }
  S3Status statusG = cloud_put_object("hashes", md5_hex, segment_len, put_buffer);
  if (statusG != S3StatusOK)
    log_msg("cloud_put: Status is %s\n", S3_get_status_name(statusG));
}

void delete_from_cloud(unsigned char *md5)
{
  char md5_hex[2 * MD5_DIGEST_LENGTH + 1] = {0};
  int i = 0;
  for (i = 0; i < MD5_DIGEST_LENGTH; i++)
  {
    sprintf(&md5_hex[i * 2], "%02x", md5[i]);
  }
  S3Status statusG = cloud_delete_object("hashes", md5_hex);
  if (statusG != S3StatusOK)
    log_msg("cloud_delete: Status is %s\n", S3_get_status_name(statusG));
}

int list_service(const char *bucketName)
{
  if (!state_.no_dedup)
  {
    if (!strcmp(bucketName, "hashes"))
      bucket_found = 1;
  }
  else
  {
    if (!strcmp(bucketName, bucket_to_find))
      bucket_found = 1;
  }

  return 0;
}

void get_bucket(const char *path, char *bucket)
{
  char *last_slash = strrchr(path, '/');
  /* No slash or last slash is start of path */
  if (last_slash == NULL || last_slash == path)
    strncpy(bucket, "root", 4);
  else
  {
    *last_slash = '\0';
    size_t len = strlen(path);
    *last_slash = '/';
    int idx = 0;
    size_t i;
    for (i = 0; i < strlen(path); i++)
    {
      if (path[i] != '/')
        break;
      idx++;
    }
    strncpy(bucket, path + idx, len - idx);
    for (i = 0; i < len; i++)
    {
      if (bucket[i] == '/')
        bucket[i] = '_';
    }
  }
}

void get_key(const char *path, char *key)
{
  char *last_slash = strrchr(path, '/');
  if (last_slash == NULL)
    strncpy(key, path, strlen(path));
  else if (last_slash < path + (strlen(path) - 1))
  {
    size_t length = strlen(path) - (size_t)(last_slash - path);
    strncpy(key, last_slash + 1, length - 1);
  }
}

static int UNUSED cloudfs_error(char *error_str)
{
  int retval = -errno;

  // TODO:
  //
  // You may want to add your own logging/debugging functions for printing
  // error messages. For example:
  //
  // debug_msg("ERROR happened. %s\n", error_str, strerror(errno));
  //

  log_msg("CloudFS Error: %s\n", error_str, strerror(errno));

  /* FUSE always returns -errno to caller (yes, it is negative errno!) */
  return retval;
}

/*
 * Initializes the FUSE file system (cloudfs) by checking if the mount points
 * are valid, and if all is well, it mounts the file system ready for usage.
 *
 */
void *cloudfs_init(struct fuse_conn_info *conn UNUSED)
{
  log_msg("cloud_init\n");
  cloud_init(state_.hostname);
  cloud_print_error();
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, "/.hash_log");
  /* If the hash table log file does not exist, then just create one */
  if (access(fpath, F_OK) == -1)
  {
    int fd = open(fpath, O_CREAT | O_EXCL | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXO);
    close(fd);
  }
  else //rebuild the hash table from the file
  {
    table_entry *reader = malloc(sizeof(table_entry));
    int fd = open(fpath, O_RDONLY);
    while (read(fd, reader, sizeof(table_entry)) > 0)
    {
      HASH_ADD_STR(hashes, md5, reader);
      reader = malloc(sizeof(table_entry));
    }
    /* The final one is always not used */
    if (reader)
      free(reader);
    close(fd);
  }
  return NULL;
}

int get_file_location(const char *path, uint8_t *file_location)
{
  if (access(path, F_OK) == -1)
    return -1;
  if (lgetxattr(path, "user.file_location", file_location, 1) < 0)
    return -1;
  return 0;
}

void cloudfs_destroy(void *data UNUSED)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, "/.hash_log");
  cloud_destroy();
  int fd = open(fpath, O_WRONLY);
  table_entry *current_hash, *tmp;
  /*Write hash table entry in hash log file */
  HASH_ITER(hh, hashes, current_hash, tmp)
  {
    HASH_DEL(hashes, current_hash);
    if (write(fd, current_hash, sizeof(table_entry)) != sizeof(table_entry))
      log_msg("Error in destroy: write fails\n");
    if (current_hash)
      free(current_hash);
  }
  fclose(logfile);
}

static int cloudfs_getattr(const char *path, struct stat *statbuf)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  if (access(fpath, F_OK) == -1)
    return -errno;
  uint8_t file_location = IN_SSD;
  get_file_location(fpath, &file_location);
  /* If file is in cloud storage */
  if (lstat(fpath, statbuf) < 0)
  {
    log_msg("error in getattr: errno is %s\n", strerror(errno));
    return -errno;
  }
  mode_t real_mode = statbuf->st_mode;
  if (file_location == IN_CLOUD)
  {
    /* Cannot get real file metadata */
    if (lgetxattr(fpath, "user.file_information", statbuf, sizeof(struct stat)) < 0)
      return -errno;
    statbuf->st_mode = real_mode;
  }
  return 0;
}

static int cloudfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  int res = lgetxattr(fpath, name, value, size);
  if (res < 0)
    return -errno;
  return res;
}

static int cloudfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  log_msg("cloudfs_setxattr: %s %s %s %d\n", fpath, name, value, size);
  if (lsetxattr(fpath, name, value, size, flags) < 0)
  {
    log_msg("setxattr failed\n");
    return -errno;
  }
  return 0;
}

static int cloudfs_mkdir(const char *path, mode_t mode)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  log_msg("cloudfs_mkdir: %s\n", fpath);
  if (mkdir(fpath, mode) < 0)
    return -errno;
  uint8_t location = IN_SSD;
  /* Set the create directory to be settled in SSD */
  if (lsetxattr(fpath, "user.file_location", &location, 1, 0) < 0)
  {
    rmdir(fpath);
    return -errno;
  }
  return 0;
}

static int cloudfs_mknod(const char *path, mode_t mode, dev_t dev)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  log_msg("cloudfs_mknod: %s\n", fpath);
  int res = 0;
  uint8_t location = IN_SSD;
  /* Set the created inode to be settled in SSD */
  if (S_ISFIFO(mode))
  {
    if (mkfifo(fpath, mode) < 0)
      return -errno;
  }
  else if (S_ISREG(mode))
  {
    if ((res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode)) < 0)
      return -errno;
    if (res >= 0)
      res = close(res);
  }
  else
  {
    if (mknod(fpath, mode, dev) < 0)
      return -errno;
  }
  if (lsetxattr(fpath, "user.file_location", &location, 1, 0) < 0)
  {
    remove(fpath);
    return -errno;
  }
  return 0;
}

void get_real_path(const char *path, char *real_path)
{
  strncpy(real_path, path, strlen(path));
  strncpy(real_path + strlen(path), ".tmp", 4);
}

void get_tmp_segment_path(const char *path, char *segment_path)
{
  strncpy(segment_path, path, strlen(path));
  strncpy(segment_path + strlen(path), ".tm2", 4);
}

static int cloudfs_open_dedup(const char *path, struct fuse_file_info *fi)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  uint8_t file_location = IN_SSD;
  get_file_location(fpath, &file_location);
  log_msg("cloudfs_open: %s %s %d\n", fpath, path, file_location);
  if (access(fpath, F_OK) == -1)
    return -errno;
  int res = open(fpath, fi->flags);
  if (res < 0)
    return -errno;
  close(res);
  return 0;
}

int cloudfs_open_nodedup_helper(const char *path, int flags)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  uint8_t file_location = IN_SSD;
  get_file_location(fpath, &file_location);
  log_msg("cloudfs_open: %s %s %d", fpath, path, file_location);
  if (access(fpath, F_OK) == -1)
    return -errno;
  int res;
  if (file_location == IN_SSD)
  {
    log_msg("\n");
    res = open(fpath, flags);
    if (res < 0)
      return -errno;
  }
  else
  {
    char real_path[MAX_PATH_LEN] = {0};
    char bucket[MAX_PATH_LEN] = {0};
    char key[MAX_PATH_LEN] = {0};
    get_real_path(fpath, real_path);
    outfile = fopen(real_path, "wb");
    get_bucket(fpath, bucket);
    get_key(fpath, key);
    log_msg(" %s %s\n", bucket, key);
    if (strlen(bucket) == 0 || strlen(key) == 0)
      return -errno;
    cloud_get_object(bucket, key, get_buffer);
    cloud_print_error();
    fclose(outfile);
    struct stat statbuf;
    if (lstat(fpath, &statbuf) < 0)
      return -errno;
    chmod(real_path, statbuf.st_mode & DEFAULT_MODE);
    if (lgetxattr(fpath, "user.file_information", &statbuf, sizeof(struct stat)) < 0)
    {
      remove(real_path);
      return -errno;
    }
    struct timespec real_time[2];
    real_time[0] = statbuf.st_atim;
    real_time[1] = statbuf.st_mtim;
    utimensat(0, real_path, real_time, AT_SYMLINK_NOFOLLOW);
    res = open(real_path, flags);
    if (res < 0)
    {
      remove(real_path);
      return -errno;
    }
  }
  return res;
}

static int cloudfs_open_nodedup(const char *path, struct fuse_file_info *fi)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  int res = cloudfs_open_nodedup_helper(fpath, fi->flags);
  if (res < 0)
    return res;
  else
    fi->fh = res;
  return 0;
}

static int cloudfs_open(const char *path, struct fuse_file_info *fi)
{
  if (!state_.no_dedup)
    return cloudfs_open_dedup(path, fi);
  else
    return cloudfs_open_nodedup(path, fi);
  return 0;
}

unsigned int get_hash_length(unsigned char *md5)
{
  table_entry *result;
  char md5_signed[2 * MD5_DIGEST_LENGTH + 1] = {0};
  int i = 0;
  for (i = 0; i < MD5_DIGEST_LENGTH; i++)
  {
    sprintf(&md5_signed[2 * i], "%02x", md5[i]);
  }
  HASH_FIND_STR(hashes, md5_signed, result);
  if (!result)
    return 0;
  return result->length;
}

ssize_t get_size(const char *fpath)
{
  struct stat statbuf;
  if (lstat(fpath, &statbuf) < 0)
    return -1;
  return statbuf.st_size;
}

void update_file_information(const char *fpath, const char *real_path)
{
  struct stat stat_fpath;
  struct stat stat_real_path;
  lgetxattr(fpath, "user.file_information", &stat_fpath, sizeof(struct stat));
  lstat(real_path, &stat_real_path);
  stat_fpath.st_atim = stat_real_path.st_atim;
  stat_fpath.st_mtim = stat_real_path.st_mtim;
  int fd = open(fpath, O_RDONLY);
  unsigned char md5[MD5_DIGEST_LENGTH];
  ssize_t size = 0;
  while (read(fd, md5, MD5_DIGEST_LENGTH) > 0)
  {
    size += get_hash_length(md5);
  }
  close(fd);
  stat_fpath.st_size = size;
  stat_fpath.st_blocks = (blkcnt_t)(stat_fpath.st_size / 512.0 + 0.5);
  lsetxattr(fpath, "user.file_information", &stat_fpath, sizeof(struct stat), 0);
}

void update_file_information_single(const char *fpath)
{
  struct stat stat_fpath;
  struct stat stat_real_path;
  lstat(fpath, &stat_fpath);
  lgetxattr(fpath, "user.file_information", &stat_real_path, sizeof(struct stat));
  stat_real_path.st_atim = stat_fpath.st_atim;
  stat_real_path.st_mtim = stat_fpath.st_mtim;
  int fd = open(fpath, O_RDONLY);
  unsigned char md5[MD5_DIGEST_LENGTH];
  ssize_t size = 0;
  while (read(fd, md5, MD5_DIGEST_LENGTH) > 0)
  {
    size += get_hash_length(md5);
  }
  close(fd);
  stat_real_path.st_size = size;
  stat_real_path.st_blocks = (blkcnt_t)(stat_real_path.st_size / 512.0 + 0.5);
  lsetxattr(fpath, "user.file_information", &stat_real_path, sizeof(struct stat), 0);
}

static int cloudfs_read_nodedup(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  log_msg("cloudfs_read: %s\n", fpath);
  int fd = fi->fh;
  if (fd == -1)
    return -errno;
  int res = pread(fd, buf, size, offset);
  if (res < 0)
    return -errno;
  return res;
}

static int cloudfs_read_dedup(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  if (access(fpath, F_OK) == -1)
    return -errno;
  uint8_t file_location;
  get_file_location(fpath, &file_location);
  if (file_location == IN_SSD)
  {
    int fd = open(fpath, fi->flags);
    if (fd < 0)
      return -errno;
    int res = pread(fd, buf, size, offset);
    if (res < 0)
    {
      close(fd);
      return -errno;
    }
    return res;
  }
  char real_path[MAX_PATH_LEN] = {0};
  get_real_path(fpath, real_path);
  ssize_t hash_size = get_size(fpath);
  if (hash_size < 0)
    return -errno;
  int fd = open(fpath, O_RDONLY);
  unsigned char *md5s = malloc(hash_size);
  memset(md5s, 0, hash_size);
  if (read(fd, md5s, hash_size) != hash_size)
    log_msg("Error in cloudfs_read: error reading all segments from file\n");
  close(fd);
  unsigned int length = 0;
  outfile = fopen(real_path, "wb");
  off_t starting_point = offset;
  ssize_t index = 0;
  size_t num_segments = 0;
  size_t total_segment_len = 0;
  /* Move relevant segments from cloud to SSD */
  while (length < offset + size && index < hash_size)
  {
    unsigned char md5[MD5_DIGEST_LENGTH + 1] = {0};
    memcpy(md5, md5s + index, MD5_DIGEST_LENGTH);
    if (length >= offset + size)
      break;
    if (length <= offset)
      starting_point = offset - length;
    length += get_hash_length(md5);
    if (length > offset)
    {
      get_from_cloud(md5);
      num_segments++;
      total_segment_len += get_hash_length(md5);
    }
    index += MD5_DIGEST_LENGTH;
  }
  fclose(outfile);
  struct stat statbuf;
  if (lgetxattr(fpath, "user.file_information", &statbuf, sizeof(struct stat)) < 0)
  {
    remove(real_path);
    return -errno;
  }
  chmod(real_path, statbuf.st_mode & DEFAULT_MODE);
  if (strstr(fpath, "helloworld.txt"))
  {
    log_msg("cloudfs_read: %s %d %lu\n", fpath, offset, size);
    log_msg("read %lu segments and a total of %lu bytes\n", num_segments, total_segment_len);
  }
  fd = open(real_path, fi->flags);
  int res = pread(fd, buf, size, starting_point);
  if (res < 0)
  {
    free(md5s);
    close(fd);
    remove(real_path);
    return -errno;
  }
  close(fd);
  /* Update proxy file information */
  remove(real_path);
  free(md5s);
  return res;
}

static int cloudfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  if (!state_.no_dedup)
    return cloudfs_read_dedup(path, buf, size, offset, fi);
  else
    return cloudfs_read_nodedup(path, buf, size, offset, fi);
  return 0;
}

int md5_exists(unsigned char *md5, int segment_len)
{
  table_entry *result = NULL;
  char md5_signed[2 * MD5_DIGEST_LENGTH + 1] = {0};
  memcpy(md5_signed, md5, MD5_DIGEST_LENGTH);
  int i = 0;
  for (i = 0; i < MD5_DIGEST_LENGTH; i++)
  {
    sprintf(&md5_signed[2 * i], "%02x", md5[i]);
  }
  HASH_FIND_STR(hashes, md5_signed, result);
  if (!result)
  {
    result = malloc(sizeof(table_entry));
    memset(result->md5, 0, 2 * MD5_DIGEST_LENGTH + 1);
    result->length = segment_len;
    result->ref_count = 1;
    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
      sprintf(&result->md5[2 * i], "%02x", md5[i]);
    }
    HASH_ADD_STR(hashes, md5, result);
    return 0;
  }
  result->ref_count++;
  return 1;
}

void upload_to_cloud(unsigned char *md5, int segment_len)
{
  /* If bucket does not exist, then create bucket */
  bucket_found = 0;
  cloud_list_service(list_service);
  if (bucket_found == 0)
    cloud_create_bucket("hashes");
  /* If md5 hash does not exist, then upload it to cloud */
  if (!md5_exists(md5, segment_len))
    put_to_cloud(md5, segment_len);
  else
  {
    char *buffer = malloc(segment_len);
    if (fread(buffer, 1, segment_len, infile) != (size_t)segment_len)
      log_msg("Error in upload_to_cloud: error in fread\n");
    free(buffer);
  }
}

void write_segments(const char *fpath, int fd, int fd2)
{
  rabinpoly_t *rp = rabin_init(state_.rabin_window_size, state_.avg_seg_size,
                               state_.min_seg_size, state_.max_seg_size);
  MD5_CTX ctx;
  unsigned char md5[MD5_DIGEST_LENGTH];
  int new_segment = 0;
  int len = 0;
  int segment_len = 0;
  char buf[1024];
  int bytes;
  MD5_Init(&ctx);
  infile = fopen(fpath, "rb");
  while ((bytes = read(fd, buf, sizeof(buf))) > 0)
  {
    char *buftoread = (char *)&buf[0];
    while ((len = rabin_segment_next(rp, buftoread, bytes,
                                     &new_segment)) > 0)
    {
      MD5_Update(&ctx, buftoread, len);
      segment_len += len;
      if (new_segment)
      {
        MD5_Final(md5, &ctx);
        if (write(fd2, md5, MD5_DIGEST_LENGTH) != MD5_DIGEST_LENGTH)
          log_msg("Error in write_segments: error in write");
        upload_to_cloud(md5, segment_len);
        MD5_Init(&ctx);
        segment_len = 0;
      }
      buftoread += len;
      bytes -= len;
      if (!bytes)
      {
        break;
      }
    }
    if (len == -1)
    {
      log_msg("Error in rabin segmentation!\n");
      return;
    }
  }
  MD5_Final(md5, &ctx);
  if (segment_len != 0)
  {
    if (write(fd2, md5, MD5_DIGEST_LENGTH) != MD5_DIGEST_LENGTH)
      log_msg("Error in write_segments: error in write");
    upload_to_cloud(md5, segment_len);
  }
  rabin_free(&rp);
  fclose(infile);
}

int segment(const char *fpath)
{
  struct stat statbuf;
  lstat(fpath, &statbuf);
  lsetxattr(fpath, "user.file_information", &statbuf, sizeof(struct stat), 0);
  uint8_t file_location = IN_CLOUD;
  lsetxattr(fpath, "user.file_location", &file_location, 1, 0);
  /* Copy all the md5 hashes from the temp file to the actual file */
  int fd = open(fpath, O_RDONLY);
  char real_path[MAX_PATH_LEN] = {0};
  get_real_path(fpath, real_path);
  char tmp_segment_file[MAX_PATH_LEN] = {0};
  get_tmp_segment_path(fpath, tmp_segment_file);
  int fd2 = open(tmp_segment_file, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
  write_segments(fpath, fd, fd2);
  close(fd);
  close(fd2);
  fd = open(fpath, O_TRUNC | O_WRONLY);
  fd2 = open(tmp_segment_file, O_RDONLY);
  unsigned char md5[MD5_DIGEST_LENGTH];
  while (read(fd2, md5, MD5_DIGEST_LENGTH) > 0)
  {
    if (write(fd, md5, MD5_DIGEST_LENGTH) != MD5_DIGEST_LENGTH)
      log_msg("Error in segment: error in writing segment to proxy file\n");
  }
  close(fd);
  close(fd2);
  remove(tmp_segment_file);
  return 0;
}

void prepare_for_write_update(unsigned char *md5)
{
  table_entry *result = NULL;
  char md5_signed[2 * MD5_DIGEST_LENGTH + 1] = {0};
  int i = 0;
  for (i = 0; i < MD5_DIGEST_LENGTH; i++)
  {
    sprintf(&md5_signed[2 * i], "%02x", md5[i]);
  }
  HASH_FIND_STR(hashes, md5_signed, result);
  if (result != NULL)
  {
    result->ref_count--;
    if (!result->ref_count)
    {
      delete_from_cloud(md5);
      HASH_DEL(hashes, result);
      free(result);
    }
  }
}

void list_segments(const char *fpath)
{
  int fd = open(fpath, O_RDONLY);
  unsigned char md5[MD5_DIGEST_LENGTH] = {0};
  log_msg("In file %s: \n", fpath);
  while (read(fd, md5, MD5_DIGEST_LENGTH) > 0)
  {
    log_msg("Hash is: ");
    int b;
    for (b = 0; b < MD5_DIGEST_LENGTH; b++)
    {
      log_msg("%02x", md5[b]);
    }
    log_msg("\nSegment length is %u\n", get_hash_length(md5));
  }
  close(fd);
}

static int cloudfs_write_dedup(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  uint8_t file_location;
  if (access(fpath, F_OK) == -1)
    return -errno;
  get_file_location(fpath, &file_location);
  if (file_location == IN_SSD)
  {
    int fd = open(fpath, fi->flags);
    int res = pwrite(fd, buf, size, offset);
    if (res < 0)
      return -errno;
    /* Threshold is reached, we should deduplicate now */
    close(fd);
    if (get_size(fpath) > state_.threshold)
    {
      /* Set xattr to show that it is actually now in cloud */
      if (segment(fpath) < 0)
        return -errno;
    }
    return res;
  }
  else
  {
    char real_path[MAX_PATH_LEN] = {0};
    get_real_path(fpath, real_path);
    int fd = open(fpath, O_RDONLY);
    unsigned char md5[MD5_DIGEST_LENGTH];
    unsigned int index = 0;
    unsigned int length = 0;
    outfile = fopen(real_path, "wb");
    off_t starting_point = offset;
    unsigned int starting_index = 0;
    unsigned int ending_index = 0;
    size_t num_segments = 0;
    size_t total_segment_len = 0;
    //list_segments(fpath);
    while (read(fd, md5, MD5_DIGEST_LENGTH) > 0)
    {
      if (length >= offset + size)
        break;
      ending_index++;
      if (length < offset)
        starting_point = offset - length;
      length += get_hash_length(md5);
      if (length >= offset)
      {
        if (length - get_hash_length(md5) < offset || length > offset + size)
        {
          get_from_cloud(md5);
          num_segments++;
          total_segment_len += get_hash_length(md5);
        }
        else
        {
          int buffer_size = get_hash_length(md5);
          char *buffer = calloc(buffer_size, 1);
          if (fwrite(buffer, 1, buffer_size, outfile) != (size_t)buffer_size)
            log_msg("Error in cloudfs_write: fwrite may have failed\n");
          if (buffer)
            free(buffer);
        }
        prepare_for_write_update(md5);
      }
      else
        starting_index++;
    }
    close(fd);
    fclose(outfile);
    struct stat statbuf;
    if (lgetxattr(fpath, "user.file_information", &statbuf, sizeof(struct stat)) < 0)
    {
      remove(real_path);
      return -errno;
    }
    chmod(real_path, statbuf.st_mode & DEFAULT_MODE);
    if (strstr(fpath, "helloworld.txt"))
    {
      log_msg("cloudfs_write: %s %d %lu\n", fpath, offset, size);
      log_msg("read %lu segments and a total of %lu bytes\n", num_segments, total_segment_len);
    }
    fd = open(real_path, fi->flags);
    int res = pwrite(fd, buf, size, starting_point);
    if (res < 0)
    {
      log_msg("Error in pwrite: %s\n", strerror(errno));
      return -errno;
    }
    close(fd);
    char temp_segment_file[MAX_PATH_LEN] = {0};
    get_tmp_segment_path(fpath, temp_segment_file);
    int fd2 = open(fpath, O_RDONLY);
    int fd3 = open(temp_segment_file, O_CREAT | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXO);
    if (fd3 < 0)
    {
      remove(real_path);
      log_msg("Error in cloudfs_write: cannot create temporary segment file, %s\n", strerror(errno));
      return -errno;
    }
    while (index < starting_index && read(fd2, md5, MD5_DIGEST_LENGTH) > 0)
    {
      if (write(fd3, md5, MD5_DIGEST_LENGTH) != MD5_DIGEST_LENGTH)
        log_msg("Error in writing segments back to file in cloudfs_write\n");
      index++;
    }
    fd = open(real_path, O_RDONLY);
    write_segments(real_path, fd, fd3);
    close(fd);
    /*Write remaining hashes from fpath to temp hash file (does not count in hashes that are changed) */
    while (read(fd2, md5, MD5_DIGEST_LENGTH) > 0)
    {
      if (index >= ending_index)
      {
        if (write(fd3, md5, MD5_DIGEST_LENGTH) != MD5_DIGEST_LENGTH)
          log_msg("Error in writing segments back to file in cloudfs_write\n");
      }
      index++;
    }
    close(fd3);
    close(fd2);
    fd2 = open(fpath, O_TRUNC | O_WRONLY);
    fd3 = open(temp_segment_file, O_RDONLY);
    /* Copy all the newest list of hashes back to proxy file */
    while (read(fd3, md5, MD5_DIGEST_LENGTH) > 0)
    {
      if (write(fd2, md5, MD5_DIGEST_LENGTH) != MD5_DIGEST_LENGTH)
        log_msg("Error in copying all segments back to proxy file\n");
    }
    close(fd2);
    /*Close and delete the temp hash file */
    close(fd3);
    remove(real_path);
    remove(temp_segment_file);
    /*
    if (strstr(fpath, "fileA.txt") || strstr(fpath, "fileB.txt"))
    {
      log_msg("After write: ");
      list_segments(fpath);
    }
    */
    return res;
  }
  return 0;
}

static int cloudfs_write_nodedup(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  int fd = fi->fh;
  if (fd == -1)
    return -errno;
  int res = pwrite(fd, buf, size, offset);
  uint8_t dirty = 1;
  uint8_t file_location = IN_SSD;
  get_file_location(path, &file_location);
  if (file_location == IN_CLOUD)
    lsetxattr(path, "user.file_dirty", &dirty, 1, 0);
  if (res < 0)
    return -errno;
  return res;
}

static int cloudfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  if (!state_.no_dedup)
    return cloudfs_write_dedup(path, buf, size, offset, fi);
  else
    return cloudfs_write_nodedup(path, buf, size, offset, fi);
  return 0;
}

static int cloudfs_release_dedup(const char *path, struct fuse_file_info *fi UNUSED)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  if (access(fpath, F_OK) == -1)
    return -errno;
  uint8_t file_location = IN_SSD;
  get_file_location(fpath, &file_location);
  log_msg("cloudfs_release: %s %d\n", fpath, file_location);
  if (file_location == IN_CLOUD)
  {
    char real_path[MAX_PATH_LEN] = {0};
    get_real_path(fpath, real_path);
    update_file_information_single(fpath);
    if (access(real_path, F_OK) != -1)
      remove(real_path);
  }
  return 0;
}

static int cloudfs_release_nodedup(const char *path, struct fuse_file_info *fi)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  if (access(fpath, F_OK) == -1)
    return -errno;
  int fd = fi->fh;
  close(fd);
  uint8_t file_location = IN_SSD;
  uint8_t next_file_location;
  get_file_location(fpath, &file_location);
  log_msg("cloudfs_release: %s %d\n", fpath, file_location);
  struct stat statbuf;
  if (lstat(fpath, &statbuf) < 0)
    return -errno;
  size_t size = statbuf.st_size;
  char real_path[MAX_PATH_LEN + 5] = {0};
  char bucket[MAX_PATH_LEN] = {0};
  char key[MAX_PATH_LEN] = {0};
  get_bucket(fpath, bucket);
  get_key(fpath, key);
  log_msg(" %s %s\n", bucket, key);
  if (strlen(bucket) == 0 || strlen(key) == 0)
    return 0;
  if (file_location == IN_SSD)
  {
    if (size > (size_t)state_.threshold)
    {
      log_msg("upload to cloud, size is %d ", size);
      next_file_location = IN_CLOUD;
      lsetxattr(fpath, "user.file_location", &next_file_location, 1, 0);
      lsetxattr(fpath, "user.file_information", &statbuf, sizeof(struct stat), 0);
      /* Change file permissions */
      //chmod(fpath, DEFAULT_MODE);
      infile = fopen(fpath, "rb");
      if (infile == NULL)
        return -errno;
      bucket_to_find = bucket;
      bucket_found = 0;
      cloud_list_service(list_service);
      if (bucket_found == 0)
        cloud_create_bucket(bucket);
      S3Status res = cloud_put_object(bucket, key, size, put_buffer);
      log_msg("put operation: %s\n", S3_get_status_name(res));
      cloud_print_error();
      fclose(infile);
      cloud_print_error();
      /* Clear file contents */
      fclose(fopen(fpath, "wb"));
      /* Restore file permissions */
      //chmod(fpath, statbuf.st_mode & DEFAULT_MODE);
    }
  }
  else
  {
    get_real_path(fpath, real_path);
    if (access(real_path, F_OK) == -1)
      return -errno;
    lstat(real_path, &statbuf);
    size = statbuf.st_size;
    log_msg("In cloud, size is %d\n", size);
    if (size > (size_t)state_.threshold)
    {
      lsetxattr(fpath, "user.file_information", &statbuf, sizeof(struct stat), 0);
      if (lgetxattr(fpath, "user.file_dirty", NULL, 0) >= 0)
      {
        //chmod(real_path, DEFAULT_MODE);
        infile = fopen(real_path, "rb");
        cloud_put_object(bucket, key, size, put_buffer);
        fclose(infile);
        lremovexattr(fpath, "user.file_dirty");
      }
      remove(real_path);
    }
    else
    {
      next_file_location = IN_SSD;
      lsetxattr(fpath, "user.file_location", &next_file_location, 1, 0);
      lremovexattr(fpath, "user.file_information");
      lremovexattr(fpath, "user.file_dirty");
      struct stat statbuf_path;
      lstat(fpath, &statbuf_path);
      //chmod(fpath, DEFAULT_MODE);
      //chmod(real_path, DEFAULT_MODE);
      /* Copy from temp file to proxy file so that the proxy file becomes the real file */
      FILE *cloud_file = fopen(real_path, "rb");
      FILE *ssd_file = fopen(fpath, "wb");
      if (cloud_file == NULL || ssd_file == NULL)
        return 0;
      char c;
      while ((c = fgetc(cloud_file)) != EOF)
      {
        fputc(c, ssd_file);
      }
      fclose(cloud_file);
      fclose(ssd_file);
      cloud_delete_object(bucket, key);
      remove(real_path);
      //chmod(fpath, statbuf_path.st_mode & DEFAULT_MODE);
      struct timespec real_time[2];
      real_time[0] = statbuf.st_atim;
      real_time[1] = statbuf.st_mtim;
      utimensat(0, fpath, real_time, AT_SYMLINK_NOFOLLOW);
    }
  }
  return 0;
}

static int cloudfs_release(const char *path, struct fuse_file_info *fi)
{
  if (!state_.no_dedup)
    return cloudfs_release_dedup(path, fi);
  else
    return cloudfs_release_nodedup(path, fi);
  return 0;
}

static int cloudfs_opendir(const char *path, struct fuse_file_info *fi)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  if (access(fpath, F_OK) == -1)
    return -errno;
  DIR *opened_dir = opendir(fpath);
  if (opened_dir == NULL)
    return -errno;
  fi->fh = (intptr_t)opened_dir;
  return 0;
}

static int cloudfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset UNUSED, struct fuse_file_info *fi UNUSED)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  DIR *dp = opendir(fpath);
  if (dp == NULL)
    return -errno;
  char realpath_lost_found[MAX_PATH_LEN] = {0};
  get_full_path(realpath_lost_found, "/lost+found");
  struct dirent *de;
  while ((de = readdir(dp)) != NULL)
  {
    char realpath_dir[MAX_PATH_LEN] = {0};
    get_full_path(realpath_dir, de->d_name);
    if (!strcmp(realpath_dir, realpath_lost_found))
      continue;
    struct stat st;
    memset(&st, 0, sizeof(st));
    st.st_ino = de->d_ino;
    st.st_mode = de->d_type << 12;
    if (filler(buf, de->d_name, &st, 0))
      break;
  }
  closedir(dp);
  return 0;
}

static int cloudfs_access(const char *path, int mask)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  if (access(fpath, mask) == -1)
    return -errno;
  return 0;
}

static int cloudfs_utimens(const char *path, const struct timespec ts[2])
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  log_msg("cloudfs_utimens: %s ", fpath);
  uint8_t file_location = IN_SSD;
  get_file_location(fpath, &file_location);
  if (file_location == IN_SSD)
  {
    if (utimensat(0, fpath, ts, AT_SYMLINK_NOFOLLOW) == -1)
      return -errno;
  }
  else
  {
    if (utimensat(0, fpath, ts, AT_SYMLINK_NOFOLLOW) == -1)
      return -errno;
    struct stat statbuf;
    if (lgetxattr(fpath, "user.file_information", &statbuf, sizeof(struct stat)) < 0)
    {
      log_msg("error getting user information\n");
      return -errno;
    }
    statbuf.st_atim = ts[0];
    statbuf.st_mtim = ts[1];
    if (lsetxattr(fpath, "user.file_information", &statbuf, sizeof(struct stat), 0) < 0)
    {
      log_msg("error setting user information\n");
      return -errno;
    }
  }
  log_msg("utimens succeeded\n");
  return 0;
}

static int cloudfs_chmod(const char *path, mode_t mode)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  if (chmod(fpath, mode) < 0)
    return -errno;
  return 0;
}

static int cloudfs_link(const char *from, const char *to)
{
  char fto[MAX_PATH_LEN] = {0};
  get_full_path(fto, to);
  char ffrom[MAX_PATH_LEN] = {0};
  get_full_path(ffrom, from);
  if (link(ffrom, fto) == -1)
    return -errno;
  return 0;
}

static int cloudfs_symlink(const char *from, const char *to)
{
  char fto[MAX_PATH_LEN] = {0};
  get_full_path(fto, to);
  char ffrom[MAX_PATH_LEN] = {0};
  get_full_path(ffrom, from);
  log_msg("cloudfs_symlink: %s %s\n", ffrom, fto);
  if (access(ffrom, F_OK) == -1)
  {
    log_msg("ffrom does not exist\n");
    return -errno;
  }
  if (symlink(ffrom, fto) == -1)
  {
    log_msg("symlink error\n");
    return -errno;
  }
  return 0;
}

static int cloudfs_readlink(const char *path, char *buf, size_t size)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  int res = readlink(fpath, buf, size - 1);
  if (res == -1)
    return -errno;
  buf[res] = '\0';
  return 0;
}

static int cloudfs_rmdir(const char *path)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  if (rmdir(fpath) == -1)
    return -errno;
  return 0;
}

static int cloudfs_unlink_dedup(const char *path)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  log_msg("cloudfs_unlink: %s\n", fpath);
  uint8_t file_location = IN_SSD;
  get_file_location(fpath, &file_location);
  if (file_location == IN_SSD)
  {
    if (unlink(fpath) == -1)
      return -errno;
  }
  else
  {
    int fd = open(fpath, O_RDONLY);
    /* Decrease reference count for every hash involved */
    unsigned char md5[MD5_DIGEST_LENGTH] = {0};
    while (read(fd, md5, MD5_DIGEST_LENGTH) > 0)
    {
      prepare_for_write_update(md5);
    }
    close(fd);
    if (unlink(fpath) == -1)
      return -errno;
  }
  return 0;
}

static int cloudfs_unlink_nodedup(const char *path)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  log_msg("cloudfs_unlink: %s\n", fpath);
  uint8_t file_location = IN_SSD;
  get_file_location(fpath, &file_location);
  if (file_location == IN_SSD)
  {
    if (unlink(fpath) == -1)
      return -errno;
  }
  else
  {
    char bucket[MAX_PATH_LEN] = {0};
    char key[MAX_PATH_LEN] = {0};
    get_bucket(fpath, bucket);
    get_key(fpath, key);
    if (strlen(bucket) == 0 || strlen(key) == 0)
      return -errno;
    cloud_delete_object(bucket, key);
    if (unlink(fpath) == -1)
      return -errno;
  }
  return 0;
}

static int cloudfs_unlink(const char *path)
{
  if (!state_.no_dedup)
    return cloudfs_unlink_dedup(path);
  else
    return cloudfs_unlink_nodedup(path);
  return 0;
}

int update_cloud_file_size(const char *fpath, off_t size)
{
  /* If size becomes smaller than threshold, put it back to SSD */
  /* If size changes but still bigger than SSD threshold, get relevant segments, modify and upload the new segments back to cloud */
  log_msg("update_cloud_file_size: Before update\n");
  list_segments(fpath);
  char real_path[MAX_PATH_LEN] = {0};
  get_real_path(fpath, real_path);
  int fd2 = open(fpath, O_RDONLY);
  unsigned int length = 0;
  off_t truncated_length = 0;
  /* Starting index of the segment that needs to be changed */
  unsigned int index = 0;
  unsigned char md5[MD5_DIGEST_LENGTH] = {0};
  infile = fopen(real_path, "rb");
  off_t offset = size;
  if (get_size(fpath) < size)
    offset = get_size(fpath);
  while (read(fd2, md5, MD5_DIGEST_LENGTH) > 0)
  {
    if (length < offset && length + get_hash_length(md5) < offset)
    {
      truncated_length += get_hash_length(md5);
      index++;
    }
    length += get_hash_length(md5);
    if (length >= offset)
    {
      if (length - get_hash_length(md5) < offset)
        get_from_cloud(md5);
      prepare_for_write_update(md5);
    }
  }
  fclose(infile);
  close(fd2);
  fd2 = open(fpath, O_RDONLY);
  int fd = open(real_path, O_RDONLY);
  if (truncate(real_path, size - truncated_length) < 0)
  {
    remove(real_path);
    return -errno;
  }
  char temp_segment_file[MAX_PATH_LEN] = {0};
  get_tmp_segment_path(fpath, temp_segment_file);
  int fd3 = open(temp_segment_file, O_CREAT | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXO);
  if (fd3 < 0)
  {
    remove(real_path);
    remove(temp_segment_file);
    return -errno;
  }
  unsigned int write_index = 0;
  while (write_index < index && read(fd2, md5, MD5_DIGEST_LENGTH) > 0)
  {
    if (write(fd3, md5, MD5_DIGEST_LENGTH) != MD5_DIGEST_LENGTH)
      log_msg("Error in cloudfs_truncate: error in write");
    write_index++;
  }
  write_segments(real_path, fd, fd3);
  close(fd);
  close(fd2);
  close(fd3);
  fd2 = open(fpath, O_WRONLY);
  fd3 = open(temp_segment_file, O_RDONLY);
  while (read(fd3, md5, MD5_DIGEST_LENGTH) > 0)
  {
    if (write(fd2, md5, MD5_DIGEST_LENGTH) != MD5_DIGEST_LENGTH)
      log_msg("Error in cloudfs_truncate: error in write");
  }
  close(fd2);
  close(fd3);
  remove(temp_segment_file);
  update_file_information(fpath, real_path);
  remove(real_path);
  log_msg("update_cloud_file_size: After update\n");
  list_segments(fpath);
  return 0;
}

int move_back_to_ssd(const char *fpath, off_t size)
{
  log_msg("move back to ssd\n");
  char real_path[MAX_PATH_LEN] = {0};
  get_real_path(fpath, real_path);
  outfile = fopen(real_path, "wb");
  int fd = open(fpath, O_RDONLY);
  unsigned char md5[MD5_DIGEST_LENGTH];
  unsigned int length = 0;
  while (read(fd, md5, MD5_DIGEST_LENGTH) > 0)
  {
    if (length < (unsigned int)state_.threshold)
    {
      get_from_cloud(md5);
      length += get_hash_length(md5);
    }
    prepare_for_write_update(md5);
  }
  fclose(outfile);
  close(fd);
  if (truncate(real_path, size) < 0)
  {
    remove(real_path);
    return -errno;
  }
  uint8_t file_location = IN_SSD;
  lremovexattr(fpath, "user.file_information");
  lsetxattr(fpath, "user.file_location", &file_location, 1, 0);
  fd = open(fpath, O_TRUNC | O_WRONLY);
  int fd2 = open(real_path, O_RDONLY);
  ssize_t file_size = get_size(real_path);
  char *buffer = malloc(file_size);
  if (buffer == NULL)
  {
    remove(real_path);
    close(fd);
    return 0;
  }
  if (read(fd2, buffer, file_size) != file_size)
    log_msg("Error in moving back to ssd: read error\n");
  if (write(fd, buffer, file_size) != file_size)
    log_msg("Error in moving back to ssd: write error\n");
  free(buffer);
  remove(real_path);
  return 0;
}

static int cloudfs_truncate_dedup(const char *path, off_t size)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  log_msg("cloudfs_truncate: %s %d\n", fpath, size);
  uint8_t file_location = IN_SSD;
  get_file_location(fpath, &file_location);
  if (file_location == IN_SSD)
  {
    if (size <= state_.threshold)
    {
      if (truncate(fpath, size) < 0)
        return -errno;
    }
    else
    {
      /* Set xattr to show that it is actually now in cloud */
      if (segment(fpath) < 0)
        return -errno;
    }
  }
  else
  {
    if (size > state_.threshold)
      return update_cloud_file_size(fpath, size);
    else
      return move_back_to_ssd(fpath, size);
  }
  return 0;
}

static int cloudfs_truncate_nodedup(const char *path, off_t size)
{
  char fpath[MAX_PATH_LEN] = {0};
  get_full_path(fpath, path);
  log_msg("cloudfs_truncate: %s %d\n", fpath, size);
  uint8_t file_location = IN_SSD;
  get_file_location(fpath, &file_location);
  if (file_location == IN_SSD)
  {
    if (truncate(fpath, size) < 0)
      return -errno;
  }
  else
  {
    char real_path[MAX_PATH_LEN] = {0};
    get_real_path(fpath, real_path);
    if (truncate(real_path, size) < 0)
      return -errno;
  }
  return 0;
}

static int cloudfs_truncate(const char *path, off_t size)
{
  if (!state_.no_dedup)
    return cloudfs_truncate_dedup(path, size);
  else
    return cloudfs_truncate_nodedup(path, size);
  return 0;
}

/*
 * Functions supported by cloudfs 
 */
static struct fuse_operations cloudfs_operations = {
    .init = cloudfs_init,
    //
    // TODO
    //
    // This is where you add the VFS functions that your implementation of
    // MelangsFS will support, i.e. replace 'NULL' with 'melange_operation'
    // --- melange_getattr() and melange_init() show you what to do ...
    //
    // Different operations take different types of parameters. This list can
    // be found at the following URL:
    // --- http://libfuse.github.io/doxygen/structfuse__operations.html
    //
    //
    .getattr = cloudfs_getattr,
    .getxattr = cloudfs_getxattr,
    .setxattr = cloudfs_setxattr,
    .mkdir = cloudfs_mkdir,
    .mknod = cloudfs_mknod,
    .open = cloudfs_open,
    .read = cloudfs_read,
    .write = cloudfs_write,
    .release = cloudfs_release,
    .opendir = cloudfs_opendir,
    .readdir = cloudfs_readdir,
    .destroy = cloudfs_destroy,
    .access = cloudfs_access,
    .utimens = cloudfs_utimens,
    .chmod = cloudfs_chmod,
    .link = cloudfs_link,
    .symlink = cloudfs_symlink,
    .readlink = cloudfs_readlink,
    .unlink = cloudfs_unlink,
    .rmdir = cloudfs_rmdir,
    .truncate = cloudfs_truncate};

int cloudfs_start(struct cloudfs_state *state,
                  const char *fuse_runtime_name)
{

  int argc = 0;
  char *argv[10];
  argv[argc] = (char *)malloc(128 * sizeof(char));
  strcpy(argv[argc++], fuse_runtime_name);
  argv[argc] = (char *)malloc(1024 * sizeof(char));
  strcpy(argv[argc++], state->fuse_path);
  argv[argc++] = "-s"; // set the fuse mode to single thread
  //argv[argc++] = "-f"; // run fuse in foreground

  state_ = *state;

  logfile = fopen("/tmp/cloudfs.log", "w");
  setvbuf(logfile, NULL, _IOLBF, 0);
  int fuse_stat = fuse_main(argc, argv, &cloudfs_operations, NULL);

  return fuse_stat;
}
