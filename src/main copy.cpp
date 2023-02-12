#include <openssl/sha.h>
#include <iostream>
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/common/data_structures/merkle_tree.tcc>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <typedef.hpp>

#include <seal/seal.h>
using namespace std;
using namespace CryptoPP;
using namespace seal;

void CalculateDigest(string &Digest, const string &Message);
bool VerifyDigest(const string &Digest, const string &Message);

void SHA256_test_function();
void AES_test_function();
string sha256(const string strSource);

Ciphertext encrypt_my() {
    cout << "接受x的加密值，并加密参数" << endl;
    // Y= w * x +b
    const int w = 5; //参数
    const int b = 8; //参数

    int x = 4;
    // Y=5*4+8=28
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 1024;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(1024);

    SEALContext context(parms);
    print_parameters(context);

    cout << "Parameter validation (success): " << context.parameter_error_message() << endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    Plaintext w_plain(to_string(w));
    Plaintext b_plain(to_string(b));
    cout << "Express w = " + to_string(w) + " as a plaintext polynomial 0x" + w_plain.to_string() + "." << endl;
    cout << "Express b = " + to_string(b) + " as a plaintext polynomial 0x" + b_plain.to_string() + "." << endl;

    Ciphertext x_encrypted;
    Plaintext x_plain(to_string(x));
    encryptor.encrypt(x_plain, x_encrypted);
    cout << "    + size of freshly encrypted x: " << x_encrypted.size() << endl; // poly number

    cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(x_encrypted) << " bits"
         << endl;
    Plaintext x_decrypted;
    cout << "    + decryption of x_encrypted: ";
    decryptor.decrypt(x_encrypted, x_decrypted);
    cout << "0x" << x_decrypted.to_string() << " ...... Correct." << endl;
    cout << "Compute w_mul_x_plus_b (w*x+b)." << endl;
    Ciphertext w_mul_x_plus_b = x_encrypted;
    evaluator.multiply_plain_inplace(w_mul_x_plus_b, w_plain);
    evaluator.add_plain_inplace(w_mul_x_plus_b, b_plain);

    Plaintext decrypted_result;
    decryptor.decrypt(w_mul_x_plus_b, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;
    cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(w_mul_x_plus_b) << " bits"
         << endl;

    auto data = w_mul_x_plus_b.data(0);
    //密文的个数为poly_modulus_degree * k, k is the number of coeff_modulus (3 in this case)
    cout << x_encrypted.poly_modulus_degree() << endl;
    cout << x_encrypted.coeff_modulus_size() << endl;
    cout << x_encrypted.size() << endl;

    // for(size_t i=0;i<x_encrypted.poly_modulus_degree();i++)
    // {
    //     cout <<i<<"++"<<*(data)<<endl;
    //     data++;
    // }
    return w_mul_x_plus_b;
}

int main() {
    ppT::init_public_params();

    G1 g = G1::random_element();
    //注册
    FieldT sk_sp = FieldT::random_element();
    G1 pk_sp = sk_sp * g;

    // 2. 对信息的哈希进行签名

    // 3. 发起request
    // user创建一次性的blockchain key pair

    // 4. confirm

    // 5. submit

    // 6. result upload

    // 7. result dispute

    // 8. self-prove
    // encrypt_my();
    SHA256_test_function();
    AES_test_function();
    cout << sha256("HelloSHA256_Filter") << endl;
    return 0;
}

void SHA256_test_function() {
    string strSource = "HelloSHA256_Filter";
    string strValue = "";
    CryptoPP::SHA256 sha256;
    StringSource ss(strSource, true, new HashFilter(sha256, new HexEncoder(new StringSink(strValue))));
    cout << strValue << endl;
}
void AES_test_function() {
    //每次加密的block为16字节，密钥长度必须为16、24、32字节之一
    // ECB
    string strKey = "www.AESKEY.com66";
    for (unsigned i = 0; i != strKey.size(); i++) {
        cout << hex << (int)strKey[i] << " ";
    }
    cout << endl;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);                    // 16字节的block用于存放密钥
    key.Assign((CryptoPP::byte *)strKey.c_str(), strKey.size()); //赋值

    for (auto it = key.begin(); it != key.end(); it++) { //打印16进制
        cout << hex << (int)(*it) << " ";
    }
    cout << endl;
}
string sha256(const string strSource) {
    // string strSource = "HelloSHA256_Filter";
    string strValue = "";
    CryptoPP::SHA256 sha256;
    StringSource ss(strSource, true, new HashFilter(sha256, new HexEncoder(new StringSink(strValue))));
    // cout << strValue<<endl;
    return strValue;
}