#ifndef __CLOUDFS_H_
#define __CLOUDFS_H_
#include "uthash.h"
#include "openssl/md5.h"
#define MAX_PATH_LEN 4096
#define MAX_HOSTNAME_LEN 1024
#define IN_SSD 0
#define IN_CLOUD 1
#define DEFAULT_MODE 00777

struct cloudfs_state {
  char ssd_path[MAX_PATH_LEN];
  char fuse_path[MAX_PATH_LEN];
  char hostname[MAX_HOSTNAME_LEN];
  int ssd_size;
  int threshold;
  int avg_seg_size;
  int min_seg_size;
  int max_seg_size;
  int rabin_window_size;
  char no_dedup;
};

typedef struct hash_table_entry {
  char md5[2 * MD5_DIGEST_LENGTH + 1];
  unsigned int length;
  unsigned int ref_count;
  UT_hash_handle hh;
} table_entry;

int cloudfs_start(struct cloudfs_state* state,
                  const char* fuse_runtime_name);  
void cloudfs_get_fullpath(const char *path, char *fullpath);
unsigned int get_hash_length(unsigned char *md5);
int segment(const char *fpath);
int md5_exists(unsigned char *md5, int segment_len);
void upload_to_cloud(unsigned char *md5, int segment_len);
void write_segments(const char *fpath, int fd, int fd2);
ssize_t get_size(const char *fpath);
void get_tmp_segment_path(const char *path, char *segment_path);
int update_cloud_file_size(const char *fpath, off_t size);
void prepare_for_write_update(unsigned char *md5);
void update_file_information(const char *fpath, const char *real_path);
void get_real_path(const char *path, char *real_path);
void list_segments(const char *fpath);
void get_bucket(const char *path, char *bucket);
void get_key(const char *path, char *key);
void update_file_information_single(const char *fpath);
#endif
