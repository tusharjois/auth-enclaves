#include <stdio.h>
#include <iostream>
#include <sys/random.h>
#include <unistd.h>
#include <chrono>
#include <thread>

#include "Enclave_u.h"
#include "Reference.hpp"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"

#define LAN_DELAY 10
#define WAN_DELAY 100
#define BENCH_ITER 100

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid_a = 0;
sgx_enclave_id_t global_eid_b = 1;

/* Similar to above, but for FakeEnclave */
FakeEnclave global_a;
FakeEnclave global_b;

// OCall implementations
void ocall_print(const char *str)
{
    printf("%s\n", str);
}

int copy_key_to_enclave(sgx_enclave_id_t eid, bool to_enclave, unsigned char *hmac_key)
{
    int retval = STATUS_OK;
    if (to_enclave)
    {
        std::cout << "Copying key from app to enclave..." << std::endl;
        ecall_generate_key(eid, &retval, hmac_key, NULL);
    }
    return retval;
}

int copy_key_to_app(FakeEnclave &enclave, bool to_app, unsigned char *hmac_key)
{
    int retval = STATUS_OK;
    if (to_app)
    {
        std::cout << "Copying key from enclave to app..." << std::endl;
        retval = enclave.fcall_generate_key(hmac_key, NULL);
    }
    return retval;
}

void add_delay(std::chrono::milliseconds delay)
{
    std::cout << "\tdelay called" << std::endl;
    std::this_thread::sleep_for(delay);
}

int main(int argc, char *argv[])
{
    bool ecall_keygen = false; // todo
    bool ecall_incoming = false;
    bool ecall_outgoing = false;
    bool lan_delay = false;
    bool wan_delay = false;

    int opt;
    while ((opt = getopt(argc, argv, "koilw")) != -1)
    {
        switch (opt)
        {
        case 'k':
            ecall_keygen = true;
            break;
        case 'o':
            ecall_outgoing = true;
            break;
        case 'i':
            ecall_incoming = true;
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
    unsigned char *hmac_key = (unsigned char *)malloc(USM_HMAC_KEY_M * sizeof(unsigned char));

    size_t total_time = 0;
    for (int i = 0; i < BENCH_ITER; i++)
    {
        auto start_time = std::chrono::steady_clock::now();

        // First, generate the HMAC key inside of the enclave.
        if (ecall_keygen)
        {
            std::cout << "Generating HMAC key in enclave..." << std::endl;
            ecall_generate_key(global_eid_a, &retval, NULL, hmac_key);
            add_delay(delay);
            ecall_generate_key(global_eid_b, &retval, hmac_key, NULL);
        }
        else
        {
            std::cout << "Generating HMAC key in app..." << std::endl;
            retval = global_a.fcall_generate_key(NULL, hmac_key);
            add_delay(delay);
            retval = global_b.fcall_generate_key(hmac_key, NULL);
        }

        if (STATUS_OK != retval)
        {
            std::cout << "Key generation failed." << std::endl;
            return 1;
        }
        // Since we're just simulating the thing anyway, fill the whole_msg with random stuff.
        unsigned char *whole_msg = (unsigned char *)malloc(2 * USM_HMAC_N * sizeof(unsigned char));
        std::cout << "A -> B: Generating message to send..." << std::endl;
        ssize_t copied_bytes = getrandom(whole_msg, 2 * USM_HMAC_N, 0);
        if (copied_bytes != 2 * USM_HMAC_N)
        {
            std::cout << "A -> B: Message generation failed." << std::endl;
            return 1;
        }

        // Now, prepare the buffer that the enclave will use for the authenticated stream.
        unsigned char *authenticated_whole_msg = (unsigned char *)malloc(2 * USM_HMAC_N * sizeof(unsigned char));

        // And we're off!
        if (ecall_outgoing)
        {
            copy_key_to_enclave(global_eid_a, !ecall_keygen, hmac_key);
            std::cout << "A -> B: Authenticating outgoing message in enclave..." << std::endl;
            ecall_authenticate_outgoing_msg(global_eid_a, &retval, whole_msg, 2 * USM_HMAC_N, authenticated_whole_msg);
        }
        else
        {
            copy_key_to_app(global_a, ecall_keygen, hmac_key);
            std::cout << "A -> B: Authenticating outgoing message in app..." << std::endl;
            retval = global_a.fcall_authenticate_outgoing_msg(whole_msg, 2 * USM_HMAC_N, authenticated_whole_msg);
        }

        if (STATUS_OK != retval)
        {
            std::cout << "A -> B: HMAC creation failed." << std::endl;
            return 1;
        }

        add_delay(delay);

        // Now, we verify the message using the enclave.
        unsigned char *verified_whole_msg = (unsigned char *)malloc(2 * USM_HMAC_N * sizeof(unsigned char));
        if (ecall_incoming)
        {
            copy_key_to_enclave(global_eid_b, !ecall_keygen || !ecall_outgoing, hmac_key);
            std::cout << "A -> B: Authenticating incoming message in enclave..." << std::endl;
            ecall_authenticate_incoming_msg(global_eid_b, &retval, authenticated_whole_msg, 2 * USM_HMAC_N, verified_whole_msg);
        }
        else
        {
            copy_key_to_app(global_b, ecall_keygen || ecall_outgoing, hmac_key);
            std::cout << "A -> B: Authenticating incoming message in app..." << std::endl;
            retval = global_b.fcall_authenticate_incoming_msg(authenticated_whole_msg, 2 * USM_HMAC_N, verified_whole_msg);
        }

        if (STATUS_OK != retval)
        {
            std::cout << "A -> B: HMAC verification failed (" << retval << ")." << std::endl;
            return 1;
        }

        // Now we go in the other direction!
        std::cout << "B -> A: Generating message to send..." << std::endl;
        copied_bytes = getrandom(whole_msg, 2 * USM_HMAC_N, 0);
        if (copied_bytes != 2 * USM_HMAC_N)
        {
            std::cout << "B -> A: Message generation failed." << std::endl;
            return 1;
        }

        if (ecall_outgoing)
        {
            copy_key_to_enclave(global_eid_b, !ecall_keygen, hmac_key);
            std::cout << "B -> A: Authenticating outgoing message in enclave..." << std::endl;
            ecall_authenticate_outgoing_msg(global_eid_b, &retval, whole_msg, 2 * USM_HMAC_N, authenticated_whole_msg);
        }
        else
        {
            copy_key_to_app(global_b, ecall_keygen, hmac_key);
            std::cout << "B -> A: Authenticating outgoing message in app..." << std::endl;
            retval = global_b.fcall_authenticate_outgoing_msg(whole_msg, 2 * USM_HMAC_N, authenticated_whole_msg);
        }

        if (STATUS_OK != retval)
        {
            std::cout << "B -> A: HMAC creation failed." << std::endl;
            return 1;
        }

        add_delay(delay);

        // Now, we verify the message using the enclave.
        if (ecall_incoming)
        {
            copy_key_to_enclave(global_eid_a, !ecall_keygen && !ecall_outgoing, hmac_key);
            std::cout << "B -> A: Authenticating incoming message in enclave..." << std::endl;
            ecall_authenticate_incoming_msg(global_eid_a, &retval, authenticated_whole_msg, 2 * USM_HMAC_N, verified_whole_msg);
        }
        else
        {
            copy_key_to_app(global_a, ecall_keygen && ecall_outgoing, hmac_key);
            std::cout << "B -> A: Authenticating incoming message in app..." << std::endl;
            retval = global_a.fcall_authenticate_incoming_msg(authenticated_whole_msg, 2 * USM_HMAC_N, verified_whole_msg);
        }

        if (STATUS_OK != retval)
        {
            std::cout << "B -> A: HMAC verification failed." << std::endl;
            return 1;
        }

        std::cout << "Success." << std::endl;
        auto end_time = std::chrono::steady_clock::now();
        total_time += std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
    }
    std::cerr << total_time / double(BENCH_ITER) << std::endl;
    return 0;
}
