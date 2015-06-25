
#include <string>

#include "login_packet.h"

class login_packet_private {
    
 public:
  login_packet_private(const string in_username,
                       const string in_password) :
    username(in_username),
    password(in_password)  {
  };
  ~login_packet_private() {
  };

  const string& get_username(void) const {
      return username;
  };
  const string& get_password(void) const {
      return password;
  };

 private:
  const string username;
  const string password;
};

explicit login_packet::login_packet(const string& resolve_packet) {
    string resolve_string(resolve_packet);

    if (!resolve_string.empty()) {
        if (!resolve_string.find(FLAG_START) || !resolve_string.find(FLAG_ACCOUNT_START) ||
            !resolve_string.find(FLAG_PASSWORD_START) || !resolve_string.find(FLAG_PASSWORD_END)) break;

        resolve_string=resolve_string.substr(DATA_OFFSET_FLAG_ACCOUNT_START+DATA_OFFSET_ACCOUNT_START,resolve_string.size());
        string resolve_account (resolve_string.substr(0,resolve_string.find_first_of(FLAG_PASSWORD_START)));
        resolve_string=resolve_string.substr(resolve_string.find_first_of(FLAG_PASSWORD_START)+DATA_OFFSET_PASSWORD_START,resolve_string.size());
        string resolve_password(resolve_string.substr(0,resolve_string.find_first_of(FLAG_PASSWORD_END)));

        if (resolve_account.empty() || resolve_password.empty()) break;

        private_data=new login_packet_private(resolve_account,resolve_password);
        return;
    }
    private_data=NULL;
}
login_packet::~login_packet() {
    if (NULL!=private_data)
        delete private_data;
    private_data=NULL;
}

string login_packet::get_username(void) const {
    return (NULL!=private_data)?private_data->get_username():NULL_STRING;
}
string login_packet::get_password(void) const {
    return (NULL!=private_data)?private_data->get_password():NULL_STRING;
}
