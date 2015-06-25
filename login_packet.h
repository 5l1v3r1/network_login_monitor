
#ifndef _LOGIN_PACKET_H__
#define _LOGIN_PACKET_H__

#include <malloc.h>
#include <memory.h>

#ifndef _INC_MATH
#include <math.h>
#endif

#ifndef _STRING_
#include <string>

using    std::string;
#endif

#ifndef NULL
#define NULL 0
#endif

#define NULL_STRING ""

static const number_table[10]={0x48,0xC8,0x49,0xC9,0x58,0xD8,0x59,0xD9,0x68,0xE8};

#define FLAG_START               (char)0x80
#define FLAG_ACCOUNT_START       (char)0x01
#define FLAG_PASSWORD_START      (char)0x08
#define FLAG_PASSWORD_END        (char)0x09

#define DATA_OFFSET_FLAG_ACCOUNT_START   26
#define DATA_OFFSET_ACCOUNT_START         2
#define DATA_OFFSET_PASSWORD_START        1

#define RESOLVE_NUMBER_ERROR -1

static bool decode_pack(unsigned char* packet_buffer,unsigned long packet_length) {
  bool result; // eax@2
  int i; // esi@5

  if ( packet_length > 0 )
  {
    if ( packet_buffer )
    {
      for ( i = 0; i < packet_length; ++i )
        packet_buffer[i] = ((unsigned __int8)(((unsigned __int8)packet_buffer[i] >> 5) | packet_buffer[i] & 0x70) >> 2) | 2 * (packet_buffer[i] & 1 | 2 * (packet_buffer[i] & 8 | 4 * (packet_buffer[i] & 4 | 4 * (packet_buffer[i] & 0xFE))));
      result = 1;
    }
    else
    {
      result = 0;
    }
  }
  else
  {
    result = 0;
  }
  return result;
}

typedef struct {
    char username[16];
    char password[20];
} userdata;

//起始标志:0x80 | 25 位数据填充标志 | 帐号起始标志:0x80 | 1 位随机填充标志 | 帐号:_____ |
//密码起始标志:0x01 | 1 位随机填充标志 | 密码:_____ | 密码结束标志:0xA0 |
//8 位数据填充标志 | 11 位未知数据 | 16 位数据填充标志
void login_packet(const string& resolve_packet,const unsigned long resolve_packet_length,userdata* output_data) {
    string resolve_string(resolve_packet);
    decode_pack((unsigned char*)resolve_string.c_str(),resolve_packet_length);

    string username;
    string password;

    memset(output_data,0,sizeof(userdata));
    resolve_string=resolve_string.substr(DATA_OFFSET_FLAG_ACCOUNT_START,resolve_string.length());
    username=resolve_string.substr(DATA_OFFSET_ACCOUNT_START,resolve_string.find_first_of(FLAG_PASSWORD_START)-3);
    resolve_string=resolve_string.substr(resolve_string.find_first_of(FLAG_PASSWORD_START),resolve_string.length());
    password=resolve_string.substr(DATA_OFFSET_PASSWORD_START,resolve_string.find_first_of(FLAG_PASSWORD_END)-1);
    memcpy(output_data->username,username.c_str(),username.length());
    memcpy(output_data->password,password.c_str(),password.length());
}

#endif
