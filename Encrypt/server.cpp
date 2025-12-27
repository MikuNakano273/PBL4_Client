// server.cpp
// Usage: server
// Compile: g++ -O2 -std=c++17 server.cpp -o server -lcrypto
//
// Server does two things:
// - On start it generates a DH keypair from dhparams.pem and writes server_pub.bin
// - Then it waits for client_pub.bin + encrypted.bin to exist, computes shared secret, derives AES key, and decrypts.
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <thread>
#include <chrono>
#include <experimental/filesystem>

static void die(const char* msg){ std::cerr<<msg<<"\n"; ERR_print_errors_fp(stderr); exit(1); }
std::vector<unsigned char> read_all(const std::string &fn){ std::ifstream f(fn,std::ios::binary); if(!f) return {}; f.seekg(0,std::ios::end); size_t n=f.tellg(); f.seekg(0); std::vector<unsigned char> b(n); f.read((char*)b.data(), n); return b; }

int main(){
    OpenSSL_add_all_algorithms(); ERR_load_crypto_strings();

    // read dh params
    FILE* f = fopen("dhparams.pem","rb");
    if(!f) die("dhparams.pem missing. Run gen_dh_params.");
    DH* dhparams = PEM_read_DHparams(f, NULL, NULL, NULL); fclose(f);
    if(!dhparams) die("PEM_read_DHparams failed");

    // create server keypair
    DH* dh = DH_new();
    const BIGNUM *p=NULL, *g=NULL;
    DH_get0_pqg(dhparams, &p, NULL, &g);
    if(!DH_set0_pqg(dh, BN_dup(p), NULL, BN_dup(g))) die("DH_set0_pqg failed");
    if(!DH_generate_key(dh)) die("DH_generate_key failed");

    // write server_pub.bin
    const BIGNUM* pub=NULL;
    DH_get0_key(dh, &pub, NULL);
    int publen = BN_num_bytes(pub);
    std::vector<unsigned char> pubbuf(publen);
    BN_bn2bin(pub, pubbuf.data());
    std::ofstream ofs("server_pub.bin", std::ios::binary); if(!ofs) die("Cannot open server_pub.bin");
    ofs.write((char*)pubbuf.data(), pubbuf.size());
    ofs.close();
    std::cout<<"Wrote server_pub.bin ("<<publen<<" bytes). Provide it to client.\n";

    // wait for client_pub.bin and encrypted.bin (simple polling)
    std::cout<<"Waiting for client_pub.bin and encrypted.bin ...\n";
    while(true){
        if(std::filesystem::exists("client_pub.bin") && std::filesystem::exists("encrypted.bin")) break;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::vector<unsigned char> client_pub = read_all("client_pub.bin");
    if(client_pub.empty()) die("client_pub.bin empty");
    BIGNUM* client_bn = BN_bin2bn(client_pub.data(), client_pub.size(), NULL);

    // compute shared secret
    int secret_size = DH_size(dh);
    std::vector<unsigned char> secret(secret_size);
    int sslen = DH_compute_key(secret.data(), client_bn, dh);
    BN_free(client_bn);
    if(sslen<=0) die("DH_compute_key failed");
    secret.resize(sslen);

    // derive aes-256 key = SHA256(shared)
    unsigned char aes_key[32];
    SHA256(secret.data(), secret.size(), aes_key);

    // open encrypted.bin, read iv(12), ciphertext, tag(16)
    std::ifstream ifs("encrypted.bin", std::ios::binary);
    if(!ifs) die("Cannot open encrypted.bin");
    unsigned char iv[12];
    ifs.read((char*)iv, sizeof(iv)); if(ifs.gcount()!=sizeof(iv)) die("Bad encrypted.bin header");

    // compute ciphertext length = file_size - iv - tag
    std::uintmax_t fsize = std::filesystem::file_size("encrypted.bin");
    if(fsize < sizeof(iv)+16) die("encrypted.bin too small");
    std::uintmax_t cipher_len = fsize - sizeof(iv) - 16;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); if(!ctx) die("EVP_CIPHER_CTX_new failed");
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) die("DecryptInit");
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL)) die("set iv len");
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv)) die("DecryptInit key/iv");

    std::ofstream ofs_dec("decrypted_out", std::ios::binary); if(!ofs_dec) die("Cannot open decrypted_out");

    const size_t CHUNK = 1024*1024;
    std::vector<unsigned char> inbuf(CHUNK), outbuf(CHUNK);
    std::uintmax_t remaining = cipher_len;
    while(remaining > 0){
        size_t toread = remaining > CHUNK ? CHUNK : (size_t)remaining;
        ifs.read((char*)inbuf.data(), toread);
        std::streamsize got = ifs.gcount();
        if(got<=0) die("Unexpected EOF during ciphertext read");
        int outl=0;
        if(1 != EVP_DecryptUpdate(ctx, outbuf.data(), &outl, inbuf.data(), got)) die("DecryptUpdate failed");
        if(outl>0) ofs_dec.write((char*)outbuf.data(), outl);
        remaining -= got;
    }

    // read tag (16)
    unsigned char tag[16];
    ifs.read((char*)tag, sizeof(tag)); if(ifs.gcount()!=sizeof(tag)) die("Missing tag");
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag)) die("Set tag failed");

    int outl_final=0;
    if(1 != EVP_DecryptFinal_ex(ctx, outbuf.data(), &outl_final)){
        std::cerr<<"Decryption failed: authentication error\n";
        EVP_CIPHER_CTX_free(ctx); return 1;
    }
    if(outl_final>0) ofs_dec.write((char*)outbuf.data(), outl_final);

    EVP_CIPHER_CTX_free(ctx);
    DH_free(dh); DH_free(dhparams);

    std::cout<<"Decrypted -> decrypted_out\n";
    return 0;
}
