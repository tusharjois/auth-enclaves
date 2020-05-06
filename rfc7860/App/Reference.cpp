#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sys/random.h>

#include "Reference.hpp"

#define USM_HMAC_KEY_M 32
#define USM_HMAC_N 24

#define STATUS_OK 1
#define STATUS_ERR_EAPI -1
#define STATUS_ERR_NKEY -2
#define STATUS_ERR_AUTH -3

unsigned char *hmac_key = NULL;

int FakeEnclave::fcall_generate_key(unsigned char* in_key, unsigned char* out_key)
{
  if (NULL == hmac_key) {
    hmac_key = (unsigned char*) malloc(USM_HMAC_KEY_M * sizeof(unsigned char));
  }
  if (NULL == in_key) {
    // Generate HMAC key, if we haven't already
    ssize_t copied_bytes = getrandom(hmac_key, USM_HMAC_KEY_M, 0);
    if (copied_bytes != USM_HMAC_KEY_M) {
        return STATUS_ERR_EAPI;
    }
  } else {
    memcpy(hmac_key, in_key, USM_HMAC_KEY_M);
  }
  if (NULL != out_key) {
    memcpy(out_key, hmac_key, USM_HMAC_KEY_M);
  }
  return STATUS_OK;
}

// Interface RFC 3414 S1.6.1, Implementation RFC 7860 S4.2.1
int FakeEnclave::fcall_authenticate_outgoing_msg(const unsigned char *whole_msg, size_t msg_len, unsigned char *authenticated_whole_msg)
{
  if (NULL == hmac_key) {
    return STATUS_ERR_NKEY;
  }

  if (msg_len <= USM_HMAC_N) {
    return STATUS_ERR_AUTH;
  }

  // Before we run the HMAC, prepare the authentication buffer.
  memcpy(authenticated_whole_msg, whole_msg, msg_len * sizeof(unsigned char));

  // Zero out the msgAuthenticationParameters.
  // We're simulating the message, so just assume the first N bytes correspond
  // to the msgAuthenticationParameters.
  memset(authenticated_whole_msg, 0, USM_HMAC_N * sizeof(unsigned char));

  // Perform the actual HMAC operation
  unsigned char auth_params[EVP_MAX_MD_SIZE] = { 0 };
  unsigned int md_len = 0; 
  unsigned char *ret = HMAC(EVP_sha256(), hmac_key, USM_HMAC_KEY_M, authenticated_whole_msg, msg_len, auth_params, &md_len);

  if (NULL == ret) {
    return STATUS_ERR_EAPI;
  }

  // Load in the auth_params from the crypto library into the output.
  memcpy(authenticated_whole_msg, auth_params, USM_HMAC_N);

  return STATUS_OK;
}

// Interface RFC 3414 S1.6.1, Implementation RFC 7860 S4.2.2
int FakeEnclave::fcall_authenticate_incoming_msg(const unsigned char *whole_msg, size_t msg_len, unsigned char *authenticated_whole_msg)
{
  if (NULL == hmac_key) {
    return STATUS_ERR_NKEY;
  }

  if (msg_len <= USM_HMAC_N) {
    return STATUS_ERR_AUTH;
  }

  // Before we run the HMAC, preserve the incoming msg_authentication_parameters.
  memcpy(authenticated_whole_msg, whole_msg, msg_len * sizeof(unsigned char));
  unsigned char incoming_auth_params[USM_HMAC_N] = { 0 };
  memcpy(incoming_auth_params, authenticated_whole_msg, USM_HMAC_N);

  // Zero out the msgAuthenticationParameters.
  // We're simulating the message, so just assume the first N bytes correspond
  // to the msgAuthenticationParameters.
  memset(authenticated_whole_msg, 0, USM_HMAC_N * sizeof(unsigned char));

  // Perform the actual HMAC operation
  unsigned char auth_params[EVP_MAX_MD_SIZE] = { 0 };
  unsigned int md_len = 0; 
  unsigned char *ret = HMAC(EVP_sha256(), hmac_key, USM_HMAC_KEY_M, authenticated_whole_msg, msg_len, auth_params, &md_len);

  if (NULL == ret) {
    return STATUS_ERR_EAPI;
  }

  // Restore the original state of the buffer.
  memcpy(authenticated_whole_msg, incoming_auth_params, USM_HMAC_N);

  // Perform the authentication comparison.
  if (0 != memcmp(incoming_auth_params, auth_params, USM_HMAC_N)) {
    return STATUS_ERR_AUTH;
  } 

  return STATUS_OK;
}
