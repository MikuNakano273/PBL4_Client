// client.cpp
// Usage: client <input_file>
// Compile: g++ -O2 -std=c++17 client.cpp -o client -lcrypto
//
// Output: client_pub.bin (public key), encrypted.bin (IV + ciphertext + tag)
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <fstream>
#include <vector>
#include <iostream>

static void die(const char* msg){
    std::cerr<<msg<<"\n"; ERR_print_errors_fp(stderr); exit(1);
}

bool write_all(const std::string &fn, const std::vector<unsigned char>& buf){
    std::ofstream f(fn, std::ios::binary); if(!f) return false; f.write((char*)buf.data(), buf.size()); return true;
}

std::vector<unsigned char> read_all(const std::string &fn){
    std::ifstream f(fn, std::ios::binary); if(!f) return {}; f.seekg(0,std::ios::end); size_t n=f.tellg(); f.seekg(0);
    std::vector<unsigned char> b(n); f.read((char*)b.data(), n); return b;
}

int main(int argc, char** argv){
    if(argc!=2){ std::cerr<<"Usage: client <input_file>\n"; return 1; }
    const char* inpath = argv[1];

    OpenSSL_add_all_algorithms(); ERR_load_crypto_strings();

    // 1) read dh params
    FILE* f = fopen("dhparams.pem","rb");
    if(!f) die("dhparams.pem missing. Run gen_dh_params.");
    DH* dhparams = PEM_read_DHparams(f, NULL, NULL, NULL); fclose(f);
    if(!dhparams) die("PEM_read_DHparams failed");

    // 2) create DH and generate keypair (ephemeral)
    DH* dh = DH_new();
    if(!dh) die("DH_new failed");
    // copy p and g from params
    const BIGNUM *p=NULL, *g=NULL;
    DH_get0_pqg(dhparams, &p, NULL, &g);
    if(!p || !g) die("invalid params");
    if(!DH_set0_pqg(dh, BN_dup(p), NULL, BN_dup(g))) die("DH_set0_pqg failed");
    if(!DH_generate_key(dh)) die("DH_generate_key failed");

    // 3) write our public key to client_pub.bin
    const BIGNUM* pub=NULL;
    DH_get0_key(dh, &pub, NULL);
    int publen = BN_num_bytes(pub);
    std::vector<unsigned char> pubbuf(publen);
    BN_bn2bin(pub, pubbuf.data());
    if(!write_all("client_pub.bin", pubbuf)) die("write client_pub.bin failed");
    std::cout<<"Wrote client_pub.bin ("<<publen<<" bytes)\n";

    // 4) load server_pub.bin (server must have created this)
    std::vector<unsigned char> server_pub = read_all("server_pub.bin");
    if(server_pub.empty()) die("server_pub.bin not found or empty");
    BIGNUM* server_bn = BN_bin2bn(server_pub.data(), server_pub.size(), NULL);

    // 5) compute shared secret
    int secret_size = DH_size(dh);
    std::vector<unsigned char> secret(secret_size);
    int sslen = DH_compute_key(secret.data(), server_bn, dh);
    BN_free(server_bn);
    if(sslen<=0) die("DH_compute_key failed");
    secret.resize(sslen);

    // 6) derive aes-256 key = SHA256(shared_secret)
    unsigned char aes_key[32];
    SHA256(secret.data(), secret.size(), aes_key);

    // 7) prepare AES-GCM
    unsigned char iv[12];
    if(RAND_bytes(iv, sizeof(iv)) != 1) die("RAND_bytes failed");
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); if(!ctx) die("EVP_CIPHER_CTX_new failed");
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) die("EncryptInit");
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL)) die("set iv len");
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv)) die("EncryptInit key/iv");

    // 8) stream read input and encrypt
    std::ifstream ifs(inpath, std::ios::binary); if(!ifs) die("Cannot open input");
    std::ofstream ofs("encrypted.bin", std::ios::binary); if(!ofs) die("Cannot open encrypted.bin");
    // header: 12 bytes iv (we will write iv first)
    ofs.write((char*)iv, sizeof(iv));

    const size_t CHUNK = 1024*1024;
    std::vector<unsigned char> inbuf(CHUNK), outbuf(CHUNK + 16);
    int outlen;
    while(ifs){
        ifs.read((char*)inbuf.data(), CHUNK);
        std::streamsize got = ifs.gcount();
        if(got<=0) break;
        if(1 != EVP_EncryptUpdate(ctx, outbuf.data(), &outlen, inbuf.data(), got)) die("EncryptUpdate failed");
        ofs.write((char*)outbuf.data(), outlen);
    }
    if(1 != EVP_EncryptFinal_ex(ctx, outbuf.data(), &outlen)) die("EncryptFinal failed");
    if(outlen>0) ofs.write((char*)outbuf.data(), outlen);

    unsigned char tag[16];
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag)) die("Get tag failed");
    ofs.write((char*)tag, sizeof(tag));

    EVP_CIPHER_CTX_free(ctx);
    DH_free(dh); DH_free(dhparams);

    std::cout<<"Encrypted -> encrypted.bin (IV + ciphertext + tag)\n";
    return 0;
}
