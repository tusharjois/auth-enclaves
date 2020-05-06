#include "Enclave_t.h"

#include <string.h>
#include "sgx_trts.h"
#include "srp.h"

#define STATUS_OK 1
#define STATUS_ERR_EAPI -1
#define STATUS_ERR_INIT -2
#define STATUS_ERR_AUTH -3

#define TEST_HASH SRP_SHA256
#define TEST_NG SRP_NG_8192

SRP_HashAlgorithm alg = TEST_HASH;
SRP_NGType ng_type = TEST_NG;

struct SRPUser *usr = NULL;
struct SRPVerifier *ver = NULL;

const char *n_hex = NULL;
const char *g_hex = NULL;

int ecall_srp_user_new(const char *username, const unsigned char *bytes_password, int len_password)
{
  usr = srp_user_new(alg, ng_type, username, bytes_password, len_password, n_hex, g_hex);
  return NULL != usr? STATUS_OK : STATUS_ERR_EAPI; 
}

int ecall_srp_user_start_authentication(const char *username,
                                        unsigned char **bytes_A, int *len_A)
{
  if (NULL == usr)
  {
    return STATUS_ERR_INIT;
  }

  const unsigned char *result_bytes_A = NULL;
  srp_user_start_authentication(usr, &username, &result_bytes_A, len_A);

  unsigned char *allocated_A = NULL;
  ocall_allocate_untrusted(&allocated_A, *len_A);
  memcpy(allocated_A, result_bytes_A, *len_A);
  *bytes_A = allocated_A;

  free((void *)result_bytes_A);
  return *len_A != 0 ? STATUS_OK : STATUS_ERR_EAPI;
}

int ecall_srp_user_process_challenge(const unsigned char *bytes_s, int len_s,
                                      const unsigned char *bytes_B, int len_B,
                                      unsigned char **bytes_M, int *len_M)
{
  const unsigned char *result_bytes_M = NULL;
  srp_user_process_challenge(usr, bytes_s, len_s, bytes_B, len_B, &result_bytes_M, len_M);

  unsigned char *allocated_M = NULL;
  ocall_allocate_untrusted(&allocated_M, *len_M);
  memcpy(allocated_M, result_bytes_M, *len_M);
  *bytes_M = allocated_M;

  return *len_M != 0 ? STATUS_OK : STATUS_ERR_EAPI;
}

void ecall_srp_user_verify_session(const unsigned char *bytes_HAMK)
{
  srp_user_verify_session(usr, bytes_HAMK);
}

int ecall_srp_user_is_authenticated(void) 
{
  return srp_user_is_authenticated(usr);
}

int ecall_srp_verifier_new(const char *username,
                           const unsigned char *bytes_s, int len_s,
                           const unsigned char *bytes_v, int len_v,
                           const unsigned char *bytes_A, int len_A,
                           unsigned char **bytes_B, int *len_B)
{
  const unsigned char *result_bytes_B = NULL;
  ver = srp_verifier_new(alg, ng_type, username, bytes_s, len_s, bytes_v, len_v, bytes_A, len_A, &result_bytes_B, len_B, n_hex, g_hex);

  unsigned char *allocated_B = NULL;
  ocall_allocate_untrusted(&allocated_B, *len_B);
  memcpy(allocated_B, result_bytes_B, *len_B);
  *bytes_B = allocated_B;

  free((void *)result_bytes_B);
  return *len_B != 0 ? STATUS_OK : STATUS_ERR_EAPI;
}

int ecall_srp_verifier_verify_session(const unsigned char *user_M, unsigned char **bytes_HAMK)
{
  const unsigned char *result_bytes_HAMK = NULL;
  srp_verifier_verify_session(ver, user_M, &result_bytes_HAMK);

  unsigned char *allocated_HAMK = NULL;
  ocall_allocate_untrusted(&allocated_HAMK, SHA256_DIGEST_LENGTH);
  memcpy(allocated_HAMK, result_bytes_HAMK, SHA256_DIGEST_LENGTH);
  *bytes_HAMK = allocated_HAMK;

  return result_bytes_HAMK != NULL ? STATUS_OK : STATUS_ERR_EAPI;
}
