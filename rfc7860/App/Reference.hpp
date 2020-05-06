#ifndef _REFERENCE_HPP
#define _REFERENCE_HPP

// usmHMAC192SHA256AuthProtocol
#define USM_HMAC_KEY_M 32
#define USM_HMAC_N 24

#define STATUS_OK 1
#define STATUS_ERR_EAPI -1
#define STATUS_ERR_NKEY -2
#define STATUS_ERR_AUTH -3

class FakeEnclave {
    public:
        int fcall_generate_key(unsigned char *in_key, unsigned char *out_key);
        int fcall_authenticate_outgoing_msg(const unsigned char *whole_msg, size_t msg_len, unsigned char *authenticated_whole_msg);
        int fcall_authenticate_incoming_msg(const unsigned char *whole_msg, size_t msg_len, unsigned char *authenticated_whole_msg);
    private:
        unsigned char* hmac_key;
};

#endif