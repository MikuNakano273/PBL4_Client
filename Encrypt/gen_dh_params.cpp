// gen_dh_params.cpp
// Compile: g++ -O2 -std=c++17 gen_dh_params.cpp -o gen_dh_params -lcrypto
//
// Generates 2048-bit DH params file dhparams.pem
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>

int main(){
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    const int bits = 2048;
    std::cout << "Generating " << bits << "-bit DH parameters (may take a while)...\n";
    DH* dh = DH_new();
    if(!dh){ std::cerr<<"DH_new failed\n"; return 1; }

    if(!DH_generate_parameters_ex(dh, bits, DH_GENERATOR_2, nullptr)){
        std::cerr<<"DH_generate_parameters_ex failed\n"; ERR_print_errors_fp(stderr);
        DH_free(dh); return 2;
    }

    FILE* f = fopen("dhparams.pem","wb");
    if(!f){ std::cerr<<"Cannot open dhparams.pem for writing\n"; DH_free(dh); return 3; }
    if(!PEM_write_DHparams(f, dh)){
        std::cerr<<"PEM_write_DHparams failed\n"; ERR_print_errors_fp(stderr);
        fclose(f); DH_free(dh); return 4;
    }
    fclose(f);
    DH_free(dh);
    std::cout<<"Wrote dhparams.pem\n";
    return 0;
}
