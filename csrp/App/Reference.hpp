#ifndef _REFERENCE_HPP
#define _REFERENCE_HPP

#define STATUS_OK 1
#define STATUS_ERR_EAPI -1
#define STATUS_ERR_INIT -2
#define STATUS_ERR_AUTH -3

#define TEST_HASH SRP_SHA256
#define TEST_NG SRP_NG_8192

class FakeEnclave
{
public:
    int fcall_srp_user_new(const char *username,
                           const unsigned char *bytes_password, int len_password);
    int fcall_srp_verifier_new(const char *username,
                               const unsigned char *bytes_s, int len_s,
                               const unsigned char *bytes_v, int len_v,
                               const unsigned char *bytes_A, int len_A,
                               unsigned char **bytes_B, int *len_B);
    int fcall_srp_user_start_authentication(const char *username,
                                            unsigned char **bytes_A, int *len_A);

    int fcall_srp_user_process_challenge(const unsigned char *bytes_s, int len_s,
                                         const unsigned char *bytes_B, int len_B,
                                         unsigned char **bytes_M, int *len_M);

    int fcall_srp_verifier_verify_session(const unsigned char *user_M, unsigned char **bytes_HAMK);
    void fcall_srp_user_verify_session(const unsigned char *bytes_HAMK);
    int fcall_srp_user_is_authenticated(void);

private:
    struct SRPUser *usr = NULL;
    struct SRPVerifier *ver = NULL;

    const char *n_hex = NULL;
    const char *g_hex = NULL;
};

#endif