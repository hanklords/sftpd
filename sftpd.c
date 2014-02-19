#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
#include <pwd.h>
#include <grp.h>


#define SSH_FXP_INIT                1
#define SSH_FXP_VERSION             2
#define SSH_FXP_OPEN                3
#define SSH_FXP_CLOSE               4
#define SSH_FXP_READ                5
#define SSH_FXP_WRITE               6
#define SSH_FXP_LSTAT               7
#define SSH_FXP_FSTAT               8
#define SSH_FXP_SETSTAT             9
#define SSH_FXP_FSETSTAT           10
#define SSH_FXP_OPENDIR            11
#define SSH_FXP_READDIR            12
#define SSH_FXP_REMOVE             13
#define SSH_FXP_MKDIR              14
#define SSH_FXP_RMDIR              15
#define SSH_FXP_REALPATH           16
#define SSH_FXP_STAT               17
#define SSH_FXP_RENAME             18
#define SSH_FXP_READLINK           19
#define SSH_FXP_LINK               21
#define SSH_FXP_BLOCK              22
#define SSH_FXP_UNBLOCK            23
#define SSH_FXP_STATUS            101
#define SSH_FXP_HANDLE            102
#define SSH_FXP_DATA              103
#define SSH_FXP_NAME              104
#define SSH_FXP_ATTRS             105
#define SSH_FXP_EXTENDED          200
#define SSH_FXP_EXTENDED_REPLY    201

#define SSH_FX_OK                            0
#define SSH_FX_EOF                           1
#define SSH_FX_NO_SUCH_FILE                  2
#define SSH_FX_PERMISSION_DENIED             3
#define SSH_FX_FAILURE                       4
#define SSH_FX_BAD_MESSAGE                   5
#define SSH_FX_NO_CONNECTION                 6
#define SSH_FX_CONNECTION_LOST               7
#define SSH_FX_OP_UNSUPPORTED                8

#define SSH_FILEXFER_ATTR_SIZE          0x00000001
#define SSH_FILEXFER_ATTR_UIDGID        0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS   0x00000004
#define SSH_FILEXFER_ATTR_ACMODTIME     0x00000008
#define SSH_FILEXFER_ATTR_EXTENDED      0x80000000
    
#define READ_DATA(data, length) do {\
  if((len_read = read(STDIN_FILENO, data, length)) == -1 || len_read == 0) \
    exit(-1); \
  in_length -= len_read; \
} while(0)

#define READ_VAR(data) do {\
  READ_DATA(&data, sizeof(data)); \
} while(0)

#define READ_STRING(data) do { /* TODO : Check data boundaries */ \
  READ_VAR(str_length); \
  READ_DATA(data, ntohl(str_length)); \
  data[ntohl(str_length)] = '\0'; \
} while(0)

#define WRITE_RESET() do {\
    _msg_length_n = 0; \
} while(0)

#define WRITE_DATA(v, s) do { \
  memcpy(_msg_data + _msg_length_n, v, s); \
  _msg_length_n += s;    \
} while(0)

#define WRITE_VAR(v) do { \
  WRITE_DATA(&v, sizeof(v)); \
} while(0)

#define WRITE_STR(str, l) do { \
  str_length = htonl(l); \
  WRITE_VAR(str_length); \
  WRITE_DATA(str, l); \
} while(0)

#define WRITE(type) do {\
  _msg_type = type; \
  _msg_length = _msg_length_n; \
  _msg_length_n += sizeof(_msg_type); \
  _msg_length_n = htonl(_msg_length_n); \
  write(STDOUT_FILENO, &_msg_length_n, sizeof(_msg_length_n));   \
  write(STDOUT_FILENO, &_msg_type, sizeof(_msg_type));   \
  write(STDOUT_FILENO, _msg_data, _msg_length);   \
  WRITE_RESET(); \
} while(0)

#define WRITE_STATUS(id, code) do {\
    error_code = htonl(code); \
    WRITE_VAR(id); \
    WRITE_VAR(error_code); \
    WRITE_STR("", 0); \
    WRITE_STR("", 0); \
    WRITE(SSH_FXP_STATUS); \
} while(0)

#define GET_RIGHT_SYMBOL(st, r, v) ((st)->st_mode & (r) ? v : '-')

char* ls_l(const char* name, const struct stat* st) {
    static char buf[2048];
    struct tm* mtime;
    struct passwd* pw;
    struct group* grp;
    char file_type_symbol;
    
    switch(st->st_mode & S_IFMT) {
        case S_IFIFO : file_type_symbol = 'p'; break;
        case S_IFCHR : file_type_symbol = 'c'; break;
        case S_IFDIR : file_type_symbol = 'd'; break;
        case S_IFBLK : file_type_symbol = 'b'; break;
        case S_IFLNK : file_type_symbol = 'l'; break;
        case S_IFSOCK: file_type_symbol = 's'; break;
        case S_IFREG : 
        default:
            file_type_symbol = '-';
    }

    mtime = localtime(&st->st_mtim.tv_sec);
    pw = getpwuid(st->st_uid);
    grp = getgrgid(st->st_gid);
    
    snprintf(buf, sizeof(buf), "%c%c%c%c%c%c%c%c%c%c %3u %8s %8s %8u %u-%02u-%02u % 2u:%02u %s",
        file_type_symbol,
        GET_RIGHT_SYMBOL(st, S_IRUSR, 'r'), GET_RIGHT_SYMBOL(st, S_IWUSR, 'w'), GET_RIGHT_SYMBOL(st, S_IXUSR, 'x'),
        GET_RIGHT_SYMBOL(st, S_IRGRP, 'r'), GET_RIGHT_SYMBOL(st, S_IWGRP, 'w'), GET_RIGHT_SYMBOL(st, S_IXGRP, 'x'),
        GET_RIGHT_SYMBOL(st, S_IROTH, 'r'), GET_RIGHT_SYMBOL(st, S_IWOTH, 'w'), GET_RIGHT_SYMBOL(st, S_IXOTH, 'x'),
        st->st_nlink, pw->pw_name, grp->gr_name, st->st_size,
        1900 + mtime->tm_year, mtime->tm_mon + 1, mtime->tm_mday, mtime->tm_hour, mtime->tm_min,
        name
    );

    return buf;
}

#define WRITE_LS_L(name, stat) do {\
    ls_l_str = ls_l(name, stat); \
    WRITE_STR(ls_l_str, strlen(ls_l_str)); \
} while(0)

#define WRITE_ATTRS(st) do {\
    attr_flags = htonl(SSH_FILEXFER_ATTR_SIZE           \
                     | SSH_FILEXFER_ATTR_UIDGID         \
                     | SSH_FILEXFER_ATTR_PERMISSIONS    \
                     | SSH_FILEXFER_ATTR_ACMODTIME      \
                );                                 \
    attr_size = htobe64((st)->st_size);                    \
    attr_uid = htonl((st)->st_uid);                 \
    attr_gid = htonl((st)->st_gid);                 \
    attr_permissions = htonl((st)->st_mode);                 \
    attr_atime = htonl((st)->st_atim.tv_sec);                 \
    attr_mtime = htonl((st)->st_mtim.tv_sec);                 \
                     \
    WRITE_VAR(attr_flags);                 \
    WRITE_VAR(attr_size);                 \
    WRITE_VAR(attr_uid); WRITE_VAR(attr_gid);                 \
    WRITE_VAR(attr_permissions);                 \
    WRITE_VAR(attr_atime); WRITE_VAR(attr_mtime);                 \
} while(0)

int main(int argc, char* argv[]) {
  uint32_t _msg_length_n, _msg_length;
  uint8_t _msg_type;
  char _msg_data[4096];
  
  ssize_t len_read;
  uint32_t in_length, str_length;
  uint8_t type;
  uint32_t version;
  uint32_t id;
  uint32_t count;
  
  /* attr */
  uint32_t attr_flags;
  uint64_t attr_size;
  uint32_t attr_uid, attr_gid;
  uint32_t attr_permissions;
  uint32_t attr_atime, attr_mtime;
  
  uint32_t error_code;
  FTS* dir_handle;
  FTSENT *ent;
  char in_buf[4096] = {0}, out_buf[4096] = {0};
  char* ls_l_str;
  char* fxp_name_count_addr;
  char* dir_path[2] = {0};
  
  struct stat st;
  
  WRITE_RESET();
  while((len_read = read(0, &in_length, sizeof(in_length))) != -1 && len_read != 0) {
    in_length = ntohl(in_length);
    READ_VAR(type);
    
    fprintf(stderr, "type: %i\n", type);
    switch(type) {
      case SSH_FXP_INIT:
        READ_VAR(version);
        
        version = htonl(3);
        WRITE_VAR(version);
        WRITE(SSH_FXP_VERSION);
        break;
        
      case SSH_FXP_REALPATH:
        READ_VAR(id);
        READ_STRING(in_buf);
        
        realpath(in_buf, out_buf);
        count = htonl(1);
        attr_flags = 0;
        
        WRITE_VAR(id);
        WRITE_VAR(count);
        WRITE_STR(out_buf, strlen(out_buf));
        WRITE_STR(out_buf, strlen(out_buf));
        WRITE_VAR(attr_flags);
        WRITE(SSH_FXP_NAME);
        break;
        
      case SSH_FXP_LSTAT:
        READ_VAR(id);
        READ_STRING(in_buf);

        if(lstat(in_buf, &st) != -1) {
            WRITE_VAR(id);
            WRITE_ATTRS(&st);
            WRITE(SSH_FXP_ATTRS);
        } else if(errno == ENOENT) {
            WRITE_STATUS(id, SSH_FX_NO_SUCH_FILE);
         } else if(errno == EACCES) {
            WRITE_STATUS(id, SSH_FX_PERMISSION_DENIED);
        } else {
            WRITE_STATUS(id, SSH_FX_FAILURE);
        }
        break;
        
      case SSH_FXP_STAT:
        READ_VAR(id);
        READ_STRING(in_buf);

        if(stat(in_buf, &st) != -1) {
            WRITE_VAR(id);
            WRITE_ATTRS(&st);
            WRITE(SSH_FXP_ATTRS);
        } else if(errno == ENOENT) {
            WRITE_STATUS(id, SSH_FX_NO_SUCH_FILE);
        } else if(errno == EACCES) {
            WRITE_STATUS(id, SSH_FX_PERMISSION_DENIED);
        } else {
            WRITE_STATUS(id, SSH_FX_FAILURE);
        }
        break;
    
      case SSH_FXP_OPENDIR:
        READ_VAR(id);
        READ_STRING(in_buf);
        dir_path[0] = in_buf;
        dir_handle = fts_open(dir_path, FTS_PHYSICAL, NULL);
        if(dir_handle && (ent = fts_read(dir_handle)) && ent->fts_info == FTS_D) {
            WRITE_VAR(id);
            WRITE_STR(&dir_handle, sizeof(dir_handle));
            WRITE(SSH_FXP_HANDLE);
        } else if(errno == ENOENT) {
            WRITE_STATUS(id, SSH_FX_NO_SUCH_FILE);
        } else if(errno == EACCES) {
            WRITE_STATUS(id, SSH_FX_PERMISSION_DENIED);
        } else {
           WRITE_STATUS(id, SSH_FX_FAILURE);
        }
        break;
        
      case SSH_FXP_READDIR:
        READ_VAR(id);
        READ_VAR(str_length);
        READ_DATA(&dir_handle, ntohl(str_length)); /* TODO: Check length == sizeof(dir_handle) */

        count = 0;
        WRITE_VAR(id);
        fxp_name_count_addr = _msg_data + _msg_length_n;
        WRITE_VAR(count);
        while((ent = fts_read(dir_handle))) {
            if(ent->fts_info == FTS_D)
              fts_set(dir_handle, ent, FTS_SKIP);
            if(ent->fts_info == FTS_DP)
              continue;
            
            count++;
            WRITE_STR(ent->fts_name, ent->fts_namelen);
            WRITE_LS_L(ent->fts_name, ent->fts_statp); /* TODO: check it is valid */
            WRITE_ATTRS(ent->fts_statp);
        }
        
        if(count > 0) {
            count = htonl(count);
            memcpy(fxp_name_count_addr, &count, sizeof(count));
            WRITE(SSH_FXP_NAME);
        } else {
            WRITE_RESET();
            WRITE_STATUS(id, SSH_FX_EOF);
        }
        break;
        
      case SSH_FXP_CLOSE:
        READ_VAR(id);
        READ_VAR(str_length);
        READ_DATA(&dir_handle, ntohl(str_length)); /* TODO: Check length == sizeof(dir_handle) */

        fts_close(dir_handle);
        
        WRITE_STATUS(id, SSH_FX_OK);
        break;
        
      default: /* Unknown command */
        fprintf(stderr, "Unknown command: %i\n", type);
        exit(-1);
        break;      
    }
    //fprintf(stderr, "remaining bytes: %i\n", in_length);
    
  }
  
  return 0;
}
