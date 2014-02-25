#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fts.h>
#include <pwd.h>
#include <grp.h>

#ifndef TIMESPEC_TO_TIMEVAL
#define TIMESPEC_TO_TIMEVAL(tv, ts) {                   \
    (tv)->tv_sec = (ts)->tv_sec;                    \
    (tv)->tv_usec = (ts)->tv_nsec / 1000;               \
}
#endif


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

#define SSH_FXF_READ            0x00000001
#define SSH_FXF_WRITE           0x00000002
#define SSH_FXF_APPEND          0x00000004
#define SSH_FXF_CREAT           0x00000008
#define SSH_FXF_TRUNC           0x00000010
#define SSH_FXF_EXCL            0x00000020

#define MIN(a,b) ((a) < (b) ? a : b)

#define READ_DATA(buffer, length) do {\
  if((len_read = read(STDIN_FILENO, buffer, length)) == -1 || (len_read == 0) || ((size_t) len_read < length)) \
    exit(-1); \
  in_length -= len_read; \
} while(0)

#define READ_VAR(v) READ_DATA(&(v), sizeof(v))
#define READ_UINT32(v) do {\
    READ_DATA(&(v), sizeof(uint32_t)); \
    v = ntohl(v); \
} while(0)

#define READ_UINT64(v) do {\
    READ_DATA(&(v), sizeof(uint64_t)); \
    v = be64toh(v); \
} while(0)

#define READ_STRING_BINARY(buffer, length) do { \
  READ_VAR(str_length); \
  str_length = ntohl(str_length); \
  if(str_length > length) {\
      WRITE_STATUS(id, SSH_FX_FAILURE); \
      exit(-1); \
  } \
  READ_DATA(buffer, str_length); \
} while(0)

#define READ_STRING(buffer, length) do {  \
  READ_STRING_BINARY(buffer, length - 1); \
  buffer[str_length] = '\0'; \
} while(0)

#define READ_ATTR(st) do { \
    memset(st, 0, sizeof(*(st))); \
    READ_UINT32(attr_flags); \
    if(attr_flags & SSH_FILEXFER_ATTR_SIZE) {\
        READ_VAR(attr_size); \
        (st)->st_size = attr_size; \
    } \
    if(attr_flags & SSH_FILEXFER_ATTR_UIDGID) {\
        READ_VAR(attr_uid); \
        (st)->st_uid = attr_uid; \
    } \
    if(attr_flags & SSH_FILEXFER_ATTR_UIDGID) {\
        READ_VAR(attr_gid); \
        (st)->st_gid = attr_gid; \
    } \
    if(attr_flags &SSH_FILEXFER_ATTR_PERMISSIONS) {\
        READ_VAR(attr_permissions); \
        (st)->st_mode = attr_permissions; \
    } \
    if(attr_flags & SSH_FILEXFER_ATTR_ACMODTIME) {\
        READ_VAR(attr_atime); \
        (st)->st_atim.tv_sec = attr_atime; \
    } \
    if(attr_flags & SSH_FILEXFER_ATTR_ACMODTIME) {\
        READ_VAR(attr_mtime); \
        (st)->st_mtim.tv_sec = attr_mtime; \
    } \
} while(0)

int fsetstat(int fd, uint32_t attr_flags, struct stat* st) {
    int ret;
    struct timeval amtimes[2];

    
    if(attr_flags & SSH_FILEXFER_ATTR_SIZE) {
        if((ret = ftruncate(fd, st->st_size)) == -1)
            return ret;
    }
    if(attr_flags & SSH_FILEXFER_ATTR_UIDGID) {
        if((ret = fchown(fd, st->st_uid, st->st_gid)) == -1)
            return ret;
    }
    if(attr_flags &SSH_FILEXFER_ATTR_PERMISSIONS) {
        if((ret = fchmod(fd, st->st_mode)) == -1)
             return ret;
    }
    if(attr_flags & SSH_FILEXFER_ATTR_ACMODTIME) {
        TIMESPEC_TO_TIMEVAL(&amtimes[0], &st->st_atim);
        TIMESPEC_TO_TIMEVAL(&amtimes[1], &st->st_mtim);
        if((ret = futimes(fd, amtimes)) == -1)
            return ret;
    }
    
    return 0;
}

#define GET_RIGHT_SYMBOL(st, r, v) ((st)->st_mode & (r) ? (v) : '-')

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

struct handle {
    enum {HANDLE_EMPTY, HANDLE_FD, HANDLE_DIR} type;
    union {
        int fd;
        FTS* dir;
    } data;
};

#define MAX_HANDLES 1024
struct handle handles[1024];

int allocate_handle(void) {
    static int n_handles;
    int i;
    
    if(n_handles > MAX_HANDLES / 2)
        return -1;
    
    do {
        i = rand();
    } while(i >= MAX_HANDLES || handles[i].type != HANDLE_EMPTY);
    
    n_handles++;
    return i;
}

#define WRITE_STRING -1
#define WRITE_UINT32 -2
#define WRITE_UINT64 -3
#define WRITE_END 0

void write_msg(uint8_t type, ...) {
    va_list ap;
    int32_t var_length;
    uint32_t msg_length = sizeof(type);
   
    /* compute message length */
    va_start(ap, type);
    for(var_length = va_arg(ap, size_t); var_length != WRITE_END; var_length = va_arg(ap, size_t)) {
        switch(var_length) {
        case WRITE_STRING:
            msg_length += sizeof(uint32_t) + strlen(va_arg(ap, char*));
            break;
        case WRITE_UINT32:
            va_arg(ap, uint32_t);
            msg_length += sizeof(uint32_t);
            break;
        case WRITE_UINT64:
            va_arg(ap, uint64_t);
            msg_length += sizeof(uint64_t);
            break;
        default:
            va_arg(ap, char*);
            msg_length += var_length;
            break;
        }
        
    }
    va_end(ap);
    
    /* message */
    msg_length = htonl(msg_length);
    write(STDOUT_FILENO, &msg_length, sizeof(msg_length));
    write(STDOUT_FILENO, &type, sizeof(type));
    va_start(ap, type);
    for(var_length = va_arg(ap, size_t); var_length != WRITE_END; var_length = va_arg(ap, size_t)) {
        char* write_str;
        uint32_t write_var32;
        uint64_t write_var64;
        
        switch(var_length) {
        case WRITE_STRING:
            write_str = va_arg(ap, char*);
            write_var32 = htonl(strlen(write_str));
            write(STDOUT_FILENO, &write_var32, sizeof(uint32_t));
            write(STDOUT_FILENO, write_str, strlen(write_str));
            break;
        case WRITE_UINT32:
            write_var32 = htonl(va_arg(ap, uint32_t));
            write(STDOUT_FILENO, &write_var32, sizeof(uint32_t));
            break;
        case WRITE_UINT64:
            write_var64 = htobe64(va_arg(ap, uint64_t));
            write(STDOUT_FILENO, &write_var64, sizeof(uint64_t));
            break;
        default:
            write(STDOUT_FILENO, va_arg(ap, char*), var_length);
            break;
        }
    }
    va_end(ap);
}

#define WRITE_VAR(v) sizeof(v), &(v)
#define WRITE_DATA(size, data) WRITE_UINT32, (size), (size), (data)

#define WRITE_STATUS(id, code) write_msg(SSH_FXP_STATUS, \
    WRITE_VAR(id), \
    WRITE_UINT32, (code), \
    WRITE_STRING, "", \
    WRITE_STRING, "", \
    WRITE_END)

void write_error(uint32_t id, int error) {
    switch(error) {
    case EBADF:
    case ENOTEMPTY:
    case ENAMETOOLONG: 
    case ENOENT:
    case ENOTDIR:
        WRITE_STATUS(id, SSH_FX_BAD_MESSAGE);
        break;
    case EACCES:
    case EPERM:
    case EROFS:
        WRITE_STATUS(id, SSH_FX_PERMISSION_DENIED);
        break;
    default:
        WRITE_STATUS(id, SSH_FX_FAILURE);
        break;
    }
}

#define WRITE_ATTRS(st) \
    WRITE_UINT32, SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME, \
    WRITE_UINT64, (st)->st_size,  \
    WRITE_UINT32, (st)->st_uid, WRITE_UINT32, (st)->st_gid, \
    WRITE_UINT32, (st)->st_mode,   \
    WRITE_UINT32, (st)->st_atim.tv_sec,\
    WRITE_UINT32, (st)->st_mtim.tv_sec

int main(void) {
  ssize_t len_read;
  uint32_t in_length, str_length;
  uint8_t type;
  uint32_t version;
  uint32_t id;
  uint32_t pflags;
  
  uint64_t file_offset;
  uint32_t file_len;

  /* attr */
  uint32_t attr_flags;
  uint64_t attr_size;
  uint32_t attr_uid, attr_gid;
  uint32_t attr_permissions;
  uint32_t attr_atime, attr_mtime;
  
  int h_index;
  int fd, fd_flags;
  FTS* dir_handle;
  FTSENT *ent;
  char in_buf[4096] = {0}, out_buf[4096] = {0};
  char* dir_path[2] = {0};
  char* data_buf;
  
  struct stat st;
  
  while((len_read = read(0, &in_length, sizeof(in_length))) != -1 && len_read != 0) {
    in_length = ntohl(in_length);
    READ_VAR(type);
    
    fprintf(stderr, "type: %i\n", type);
    switch(type) {
      case SSH_FXP_INIT:
        READ_VAR(version);
        
        write_msg(SSH_FXP_VERSION,
            WRITE_UINT32, 3,
            WRITE_END
        );
        break;
        
      case SSH_FXP_REALPATH:
        READ_VAR(id);
        READ_STRING(in_buf, sizeof(in_buf));
        
        realpath(in_buf, out_buf);
        attr_flags = 0;
        
        write_msg(SSH_FXP_NAME,
            WRITE_VAR(id),
            WRITE_UINT32, 1,
            WRITE_STRING, out_buf, WRITE_STRING, "", WRITE_VAR(attr_flags),
            WRITE_END
        );
        break;
        
      case SSH_FXP_OPEN:
          READ_VAR(id);
          READ_STRING(in_buf, sizeof(in_buf));
          READ_UINT32(pflags);
          READ_ATTR(&st);
          
          /* Check fxp_open attributes */
          if(pflags & SSH_FXF_READ & SSH_FXF_WRITE)
              fd_flags = O_RDWR;
          else if(pflags & SSH_FXF_READ)
              fd_flags = O_RDONLY;
          else if(pflags & SSH_FXF_WRITE)
              fd_flags = O_RDWR;
          else {
              WRITE_STATUS(id, SSH_FX_BAD_MESSAGE);
              break;
          }

          if(pflags & SSH_FXF_APPEND)
              fd_flags |= O_APPEND;
          if(pflags & SSH_FXF_CREAT)
              fd_flags |= O_CREAT;
          if(pflags & SSH_FXF_TRUNC)
              fd_flags |= O_TRUNC;
          if(pflags & SSH_FXF_EXCL)
              fd_flags |= O_EXCL;
          
          if(((pflags & SSH_FXF_EXCL) || (pflags & SSH_FXF_TRUNC)) && !(pflags & SSH_FXF_CREAT)) {
               WRITE_STATUS(id, SSH_FX_BAD_MESSAGE);
               break;
          }
          
          /* TODO: set the right attrs */
          if(pflags & SSH_FXF_CREAT) {
              fd = open(in_buf, fd_flags, 0644);
          } else {
              fd = open(in_buf, fd_flags);
          }
          
          if(fd != -1) {
             h_index = allocate_handle();
             if(h_index == -1) {
                 WRITE_STATUS(id, SSH_FX_FAILURE);
                 break;
             }
             
             handles[h_index].type = HANDLE_FD;
             handles[h_index].data.fd = fd;
             
             write_msg(SSH_FXP_HANDLE,
                 WRITE_VAR(id),
                 WRITE_DATA(sizeof(h_index), &h_index),
                 WRITE_END
             );
          } else if(errno == ENOENT) {
              WRITE_STATUS(id, SSH_FX_NO_SUCH_FILE);
          } else if(errno == EACCES) {
              WRITE_STATUS(id, SSH_FX_PERMISSION_DENIED);
          } else {
              WRITE_STATUS(id, SSH_FX_FAILURE);
          }
          break;
          
      case SSH_FXP_READ:
          READ_VAR(id);
          READ_STRING_BINARY(&h_index, sizeof(h_index));
          READ_UINT64(file_offset);
          READ_UINT32(file_len);
          
          if(h_index < 0 || h_index >= MAX_HANDLES || handles[h_index].type != HANDLE_FD) {
              WRITE_STATUS(id, SSH_FX_BAD_MESSAGE);
              break;
          }
          
          fd = handles[h_index].data.fd;
          fstat(fd, &st);
          
          file_len = MIN(st.st_size - file_offset, file_len);
          if(file_offset >= (uint64_t) st.st_size) {
              WRITE_STATUS(id, SSH_FX_EOF);
              break;
          }
          
          data_buf = mmap(NULL, file_len, PROT_READ, MAP_SHARED, fd, file_offset);
          if(data_buf == MAP_FAILED) {
              write_error(id, errno);
          } else {
              write_msg(SSH_FXP_DATA,
                  WRITE_VAR(id),
                  WRITE_DATA(file_len, data_buf),
                  WRITE_END
              );
              munmap(data_buf, file_len);
          }
          break;

      case SSH_FXP_WRITE:
          READ_VAR(id);
          READ_STRING_BINARY(&h_index, sizeof(h_index));
        
          if(h_index < 0 || h_index >= MAX_HANDLES || handles[h_index].type != HANDLE_FD) {
              WRITE_STATUS(id, SSH_FX_BAD_MESSAGE);
              break;
          }
          fd = handles[h_index].data.fd;

          READ_UINT64(file_offset);
          READ_UINT32(file_len);
          
          ftruncate(fd, file_offset + file_len);
          data_buf = mmap(NULL, file_len, PROT_WRITE, MAP_SHARED, fd, file_offset);
          if(data_buf == MAP_FAILED) {
              write_error(id, errno);
          } else {
              READ_DATA(data_buf, file_len);
              WRITE_STATUS(id, SSH_FX_OK);
              munmap(data_buf, file_len);
          }
          break;
          
    case SSH_FXP_REMOVE:
        READ_VAR(id);
        READ_STRING(in_buf, sizeof(in_buf));
        
        if(unlink(in_buf) == -1) {
            write_error(id, errno);
        } else {
            WRITE_STATUS(id, SSH_FX_OK);
        }
        break;
        
    case SSH_FXP_RMDIR:
        READ_VAR(id);
        READ_STRING(in_buf, sizeof(in_buf));
        
        if(rmdir(in_buf) == -1) {
            write_error(id, errno);
        } else {
            WRITE_STATUS(id, SSH_FX_OK);
        }
        break;
        
    case SSH_FXP_SETSTAT: /* TODO: return errors */
        READ_VAR(id);
        READ_STRING(in_buf, sizeof(in_buf));
        READ_ATTR(&st);
        
        fd = open(in_buf, O_WRONLY);
        fsetstat(fd, attr_flags, &st);
        close(fd);
        break;
        
    case SSH_FXP_FSETSTAT: /* TODO: return errors */
        READ_VAR(id);
        READ_STRING_BINARY(&h_index, sizeof(h_index));
        
        if(h_index < 0 || h_index >= MAX_HANDLES || handles[h_index].type != HANDLE_FD) {
            WRITE_STATUS(id, SSH_FX_BAD_MESSAGE);
            break;
        }
        fd = handles[h_index].data.fd;
        READ_ATTR(&st);
        
        fsetstat(fd, attr_flags, &st);
        break;
        
    case SSH_FXP_FSTAT:
        READ_VAR(id);
        READ_STRING_BINARY(&h_index, sizeof(h_index));
        
        if(h_index < 0 || h_index >= MAX_HANDLES || handles[h_index].type != HANDLE_FD) {
            WRITE_STATUS(id, SSH_FX_BAD_MESSAGE);
            break;
        }
        fd = handles[h_index].data.fd;

        if(fstat(fd, &st) != -1) {
            write_msg(SSH_FXP_ATTRS,
                WRITE_VAR(id),
                WRITE_ATTRS(&st),
                WRITE_END
            );
        } else if(errno == ENOENT) {
            WRITE_STATUS(id, SSH_FX_NO_SUCH_FILE);
        } else if(errno == EACCES) {
            WRITE_STATUS(id, SSH_FX_PERMISSION_DENIED);
        } else {
            WRITE_STATUS(id, SSH_FX_FAILURE);
        }
        break;
        
      case SSH_FXP_LSTAT:
        READ_VAR(id);
        READ_STRING(in_buf, sizeof(in_buf));

        if(lstat(in_buf, &st) != -1) {
            write_msg(SSH_FXP_ATTRS,
                WRITE_VAR(id),
                WRITE_ATTRS(&st),
                WRITE_END
            );
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
        READ_STRING(in_buf, sizeof(in_buf));

        if(stat(in_buf, &st) != -1) {
            write_msg(SSH_FXP_ATTRS,
                WRITE_VAR(id),
                WRITE_ATTRS(&st),
                WRITE_END
            );
        } else if(errno == ENOENT) {
            WRITE_STATUS(id, SSH_FX_NO_SUCH_FILE);
        } else if(errno == EACCES) {
            WRITE_STATUS(id, SSH_FX_PERMISSION_DENIED);
        } else {
            WRITE_STATUS(id, SSH_FX_FAILURE);
        }
        break;
        
    case SSH_FXP_MKDIR:
        READ_VAR(id);
        READ_STRING(in_buf, sizeof(in_buf));
        READ_ATTR(&st);
        
        if(mkdir(in_buf, st.st_mode) == -1) {
            switch(errno) {
            case ENOTDIR:
            case ENAMETOOLONG:
            case ENOENT:
                WRITE_STATUS(id, SSH_FX_BAD_MESSAGE);
                break;
            case EDQUOT:
            case EACCES:
            case EPERM:
            case EROFS:
                WRITE_STATUS(id, SSH_FX_PERMISSION_DENIED);
                break;
            default:
                WRITE_STATUS(id, SSH_FX_FAILURE);
                break;
            }
        } else {
            WRITE_STATUS(id, SSH_FX_OK);
        }
        break;

      case SSH_FXP_OPENDIR:
        READ_VAR(id);
        READ_STRING(in_buf, sizeof(in_buf));
        
        dir_path[0] = in_buf;
        dir_handle = fts_open(dir_path, FTS_PHYSICAL, NULL);
        if(dir_handle && (ent = fts_read(dir_handle)) && ent->fts_info == FTS_D) {
            h_index = allocate_handle();
            if(h_index == -1) {
                 WRITE_STATUS(id, SSH_FX_FAILURE);
                 break;
            }
            handles[h_index].type = HANDLE_DIR;
            handles[h_index].data.dir = dir_handle;
            
            write_msg(SSH_FXP_HANDLE,
                WRITE_VAR(id),
                WRITE_DATA(sizeof(h_index), &h_index),
                WRITE_END
            );
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
        READ_STRING_BINARY(&h_index, sizeof(h_index));
        
        if(h_index < 0 || h_index >= MAX_HANDLES || handles[h_index].type != HANDLE_DIR) {
            WRITE_STATUS(id, SSH_FX_BAD_MESSAGE);
            break;
        }
          
        dir_handle = handles[h_index].data.dir;
        while((ent = fts_read(dir_handle)) && ent->fts_info == FTS_DP);
        if(ent) {
            if(ent->fts_info == FTS_D)
              fts_set(dir_handle, ent, FTS_SKIP);
            
            write_msg(SSH_FXP_NAME,
                WRITE_VAR(id),
                WRITE_UINT32, 1,
                WRITE_DATA(ent->fts_namelen, ent->fts_name),
                WRITE_STRING, ls_l(ent->fts_name, ent->fts_statp), /* TODO: check it is valid */
                WRITE_ATTRS(ent->fts_statp),
                WRITE_END
            );
        } else {
            WRITE_STATUS(id, SSH_FX_EOF);
        }
        break;
        
      case SSH_FXP_CLOSE:
        READ_VAR(id);
        READ_STRING_BINARY(&h_index, sizeof(h_index));
        
        if(h_index < 0 || h_index >= MAX_HANDLES || handles[h_index].type == HANDLE_EMPTY) {
            WRITE_STATUS(id, SSH_FX_BAD_MESSAGE);
            break;
        }
        
        if(handles[h_index].type == HANDLE_DIR)
            fts_close(handles[h_index].data.dir);
        else if(handles[h_index].type == HANDLE_FD)
            close(handles[h_index].data.fd);
        
        handles[h_index].type = HANDLE_EMPTY;
        
        WRITE_STATUS(id, SSH_FX_OK);
        break;
        
      default: /* Unknown command */
        fprintf(stderr, "Unknown command: %i\n", type);
        exit(-1);
        break;      
    }
    /* TODO: read remaining bytes */
    while(in_length > 0)
        READ_DATA(in_buf, MIN(sizeof(in_buf), in_length));
    //fprintf(stderr, "remaining bytes: %i\n", in_length); 
  }
  
  return 0;
}
