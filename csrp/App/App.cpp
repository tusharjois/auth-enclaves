#include <stdio.h>
#include <iostream>
#include <sys/random.h>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <cstring>

#include "Enclave_u.h"
#include "Reference.hpp"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include "srp.h"

#define LAN_DELAY 10
#define WAN_DELAY 100
#define BENCH_ITER 100

#define TEST_HASH SRP_SHA256
#define TEST_NG SRP_NG_8192

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid_a = 0;
sgx_enclave_id_t global_eid_b = 1;

/* Similar to above, but for FakeEnclave */
FakeEnclave global_a;
FakeEnclave global_b;

const char *test_n_hex = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496"
                         "EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8E"
                         "F4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA"
                         "9AFD5138FE8376435B9FC61D2FC0EB06E3";
const char *test_g_hex = "2";

// OCall implementations
void ocall_print(const char *str)
{
    printf("%s\n", str);
}

void ocall_allocate_untrusted(unsigned char **bytes, size_t nbytes)
{
    *bytes = (unsigned char *)malloc(nbytes * sizeof(unsigned char));
}

void add_delay(std::chrono::milliseconds delay)
{
    std::cout << "\tdelay called" << std::endl;
    std::this_thread::sleep_for(delay);
}

int main(int argc, char *argv[])
{
    bool ecall_usr = false;
    bool ecall_ver = false;
    bool lan_delay = false;
    bool wan_delay = false;

    int opt;
    while ((opt = getopt(argc, argv, "uvlw")) != -1)
    {
        switch (opt)
        {
        case 'u':
            ecall_usr = true;
            break;
        case 'v':
            ecall_ver = true;
            break;
        case 'l':
            lan_delay = true;
            break;
        case 'w':
            wan_delay = true;
            break;
        }
    }

    std::chrono::milliseconds delay(wan_delay ? WAN_DELAY : (lan_delay ? LAN_DELAY : 0));

    std::cout << "Initializing enclave..." << std::endl;
    if (initialize_enclave(&global_eid_a, "enclave.token", "enclave.signed.so") < 0)
    {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }

    if (initialize_enclave(&global_eid_b, "enclave.token", "enclave.signed.so") < 0)
    {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }

    int retval = -1;

    const char *username = "testuser";
    const char *password = "password";

    SRP_HashAlgorithm alg = TEST_HASH;
    SRP_NGType ng_type = TEST_NG;

    const char *auth_username = 0;
    const char *n_hex = 0;
    const char *g_hex = 0;

    const unsigned char *bytes_s = NULL;
    const unsigned char *bytes_v = NULL;

    int len_s = 0;
    int len_v = 0;

    srp_create_salted_verification_key(alg, ng_type, username,
                                       (const unsigned char *)password,
                                       strlen(password),
                                       &bytes_s, &len_s, &bytes_v, &len_v, n_hex, g_hex);

    size_t total_time = 0;

    for (int i = 0; i < BENCH_ITER; i++)
    {
        auto start_time = std::chrono::steady_clock::now();
        int retval = -1;
        std::cout << "Creating user and starting authentication..." << std::endl;
        if (ecall_usr)
        {
            ecall_srp_user_new(global_eid_a, &retval, username, (const unsigned char *)password, strlen(password));
        } else {
            retval = global_a.fcall_srp_user_new(username, (const unsigned char *)password, strlen(password));
        }
        if (STATUS_OK != retval)
        {
            std::cout << "User creation failed (" << retval << ")." << std::endl;
            return -1;
        }
        unsigned char *bytes_A = NULL;
        int len_A = 0;
        if (ecall_usr)
        {
            ecall_srp_user_start_authentication(global_eid_a, &retval, username, &bytes_A, &len_A);
        } else {
            retval = global_a.fcall_srp_user_start_authentication(username, &bytes_A, &len_A);
        }
        if (STATUS_OK != retval)
        {
            std::cout << "Authentication start failed (" << retval << ")." << std::endl;
            return -1;
        }

        std::cout << "User -> Host: (username, bytes_A)" << std::endl;
        add_delay(delay);
        unsigned char *bytes_B = NULL;
        int len_B = 0;
        if (ecall_ver)
        {
            ecall_srp_verifier_new(global_eid_b, &retval, username, bytes_s, len_s, bytes_v, len_v, bytes_A, len_A, &bytes_B, &len_B);
        } else {
            retval = global_b.fcall_srp_verifier_new(username, bytes_s, len_s, bytes_v, len_v, bytes_A, len_A, &bytes_B, &len_B);
        }
        if (STATUS_OK != retval)
        {
            std::cout << "Verifier creation failed (" << retval << ")." << std::endl;
            return -1;
        }

        std::cout << "Host -> User: (bytes_s, bytes_B)" << std::endl;
        add_delay(delay);
        unsigned char *bytes_M = NULL;
        int len_M = 0;
        if (ecall_usr)
        {
            ecall_srp_user_process_challenge(global_eid_a, &retval, bytes_s, len_s, bytes_B, len_B, &bytes_M, &len_M);
        } else {
            global_a.fcall_srp_user_process_challenge(bytes_s, len_s, bytes_B, len_B, &bytes_M, &len_M);
        }
        if (STATUS_OK != retval)
        {
            std::cout << "User challenge processing failed (" << retval << ")." << std::endl;
            return -1;
        }

        std::cout << "User -> Host: (bytes_M)" << std::endl;
        add_delay(delay);
        unsigned char *bytes_HAMK = NULL;
        int len_HAMK = 0;
        if (ecall_ver)
        {
            ecall_srp_verifier_verify_session(global_eid_b, &retval, bytes_M, &bytes_HAMK);
        } else {
            retval = global_b.fcall_srp_verifier_verify_session(bytes_M, &bytes_HAMK);
        }
        if (STATUS_OK != retval)
        {
            std::cout << "Verifier session verification failed (" << retval << ")." << std::endl;
            return -1;
        }

        std::cout << "Host -> User: (bytes_HAMK)" << std::endl;
        add_delay(delay);
        if (ecall_usr)
        {
            ecall_srp_user_verify_session(global_eid_a, bytes_HAMK);
            ecall_srp_user_is_authenticated(global_eid_a, &retval);
        } else {
            global_a.fcall_srp_user_verify_session(bytes_HAMK);
            retval = global_a.fcall_srp_user_is_authenticated();
        }
        if (!retval)
        {
            std::cout << "User session verification failed (" << retval << ")." << std::endl;
            return -1;
        }

        std::cout << "Success." << std::endl;
        auto end_time = std::chrono::steady_clock::now();
        total_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
    }
    std::cerr << total_time / double(BENCH_ITER) << std::endl;
    return 0;
}
