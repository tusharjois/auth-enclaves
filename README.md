# auth-enclaves

Code for "Bringing Secure Enclaves to Distributed Authentication Protocols", a
final project by Tushar Jois and Max Zinkus for JHU Advanced Operating Systems,
Spring 2020.

THIS IS RESEARCH CODE, AND HAS NOT BEEN AUDITED FOR PRODUCTION USE.

## Building & Running

The two folders, `csrp` and `rfc7860`, correspond to the implementations of
`SRP` and `HMAC-SHA-2`, respectively. The `bench.bash` script in each runs the
benchmarks that we developed for this project. It also invokes `make` for each
project; assuming a standard configuration, the code should build with no
issues.

The code assumes that both the SGX SDK and SGK SSL libraries are installed. The
default locations for these are `/opt/intel/sgxsdk` and `/opt/intel/sgxssl`, and
are coded into the `Makefile` for each; modify the `Makefile` in order to
provide a different location. These libraries are needed at runtime, even for
simulated enclaves. Installation instructions can be found for the 
[SGX SDK](https://github.com/intel/linux-sgx) and for 
[SGX SSL](https://github.com/intel/intel-sgx-ssl) at their associated repositories.

Our testbed machine was running Ubuntu 18.04, with SGX SDK version 2.9 (built
without mitigations)as well as the associated SGX SSL version (OpenSSL 1.1.1d).
The machine also did not run SGX natively, so we built our tests in simulation
mode. 

## Attribution

We use code from two places: (1) the [template enclave](https://github.com/digawp/hello-enclave) and (2) the OpenSSL-compatible [SRP library](https://github.com/cocagne/csrp). We made modifications to both in order to fit our unique model, along with writing our own Enclave code to integrate everything together. 
