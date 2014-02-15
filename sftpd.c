#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>


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

#define READ_DATA(data) do {\
  if((len_read = read(STDIN_FILENO, &data, sizeof(data))) == -1 || len_read == 0) \
    exit(-1); \
  in_length -= len_read; \
} while(0)

#define READ_STRING(data) do {\
  READ_DATA(str_length); \
  if((len_read = read(STDIN_FILENO, data, ntohl(str_length))) == -1 || len_read == 0) \
    exit(-1); \
  data[ntohl(str_length)] = '\0';\
  in_length -= len_read; \
} while(0)

#define WRITE_DATA(var, data) do { \
  var = data;\
  write(STDOUT_FILENO, &var, sizeof(var)); \
} while(0)

#define WRITE_STR(data) do { \
  WRITE_DATA(str_length, htonl(strlen(data))); \
  write(STDOUT_FILENO, data, ntohl(str_length)); \
} while(0)

int main(int argc, char* argv[]) {
  ssize_t len_read;
  uint32_t in_length, out_length, str_length;
  uint8_t type;
  uint32_t version;
  uint32_t id;
  char in_buf[4096], out_buf[4096];
  
  while((len_read = read(0, &in_length, sizeof(in_length))) != -1 && len_read != 0) {
    in_length = ntohl(in_length);
    fprintf(stderr, "length: %i\n", in_length);
    READ_DATA(type);
    fprintf(stderr, "type: %i\n", type);

    switch(type) {
      case SSH_FXP_INIT:
        READ_DATA(version);
        fprintf(stderr, "version: %i\n", ntohl(version));
        
        
        WRITE_DATA(out_length, htonl(sizeof(version) + 1));
        WRITE_DATA(type, SSH_FXP_VERSION);
        WRITE_DATA(version, htonl(3));
        break;
        
      case SSH_FXP_REALPATH:
        READ_DATA(id);
        fprintf(stderr, "id: 0x%x\n", id);
        
        READ_STRING(in_buf);
        fprintf(stderr, "%.*s\n", str_length, in_buf);
        
        realpath(in_buf, out_buf);
        fprintf(stderr, "%s\n", out_buf);
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
