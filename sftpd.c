#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <dirent.h>


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


#define READ_DATA(data, length) do {\
  if((len_read = read(STDIN_FILENO, data, length)) == -1 || len_read == 0) \
    exit(-1); \
  in_length -= len_read; \
} while(0)

#define READ_VAR(data) do {\
  READ_DATA(&data, sizeof(data)); \
} while(0)

#define READ_STRING(data) do {\
  READ_VAR(str_length); \
  READ_DATA(data, ntohl(str_length)); \
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
} while(0);

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
  uint32_t flags;
  uint32_t error_code;
  int handle;
  DIR* dir;
  struct dirent* ent;
  char in_buf[4096] = {0}, out_buf[4096] = {0};
  char* fxp_name_count_addr;
  
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
        id = id;
        count = htonl(1);
        flags = 0;
        
        WRITE_VAR(id);
        WRITE_VAR(count);
        WRITE_STR(out_buf, strlen(out_buf));
        WRITE_STR(out_buf, strlen(out_buf));
        WRITE_VAR(flags);
        WRITE(SSH_FXP_NAME);
        break;
        
      case SSH_FXP_OPENDIR:
        READ_VAR(id);
        
        READ_STRING(in_buf);
        handle = open(in_buf, O_RDONLY);
        
        id = id;

        WRITE_VAR(id);
        WRITE_STR(&handle, sizeof(handle));
        WRITE(SSH_FXP_HANDLE);
        break;
        
      case SSH_FXP_READDIR:
        READ_VAR(id);
        READ_VAR(str_length);
        READ_DATA(&handle, ntohl(str_length)); /* Check length == sizeof(handle) */

        dir = fdopendir(handle);
        
        id = id;
        count = 0;
        WRITE_VAR(id);
        fxp_name_count_addr = _msg_data + _msg_length_n;
        WRITE_VAR(count);
        while(dir && (ent = readdir(dir))) {
            if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
                continue;
            
            count++;
            flags = 0;
            
            WRITE_STR(ent->d_name, strlen(ent->d_name));
            WRITE_STR(ent->d_name, strlen(ent->d_name));
            WRITE_VAR(flags);
        }
        
        if(count > 0) {
            closedir(dir);
            count = htonl(count);
            memcpy(fxp_name_count_addr, &count, sizeof(count));
            WRITE(SSH_FXP_NAME);
        } else {
            WRITE_RESET();
            WRITE_STATUS(id, SSH_FX_EOF)
        }
        break;
        
      case SSH_FXP_CLOSE:
        READ_VAR(id);
        READ_VAR(str_length);
        READ_DATA(&handle, ntohl(str_length)); /* Check length == sizeof(handle) */

        close(handle);
        
        WRITE_STATUS(id, SSH_FX_OK)
        break;
        
      default: /* Unknown command */
        fprintf(stderr, "Unknown command: %i\n", type);
        exit(-1);
        break;      
    }
    fprintf(stderr, "remaining bytes: %i\n", in_length);
    
  }
  
  return 0;
}
