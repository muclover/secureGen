#include "../algorithm.hpp"
#include "../timer.hpp"
#include <iostream>

using namespace std;
using namespace seal;

const int mul_size = 1;
int main()
{
    Timer timer;
    EncryptionParameters enc_params(scheme_type::bfv);
    // // generate encrypt handler
    uint32_t N = 32768; //32768
    // uint32_t N = 8192;             //32768
    uint64_t plain_modulus = 1024; // 786433
    // uint32_t logt = 20;

    gen_encryption_params(N, plain_modulus, enc_params);
    Encryptor_Help my_enc_tool(enc_params);
    print_parameters(*my_enc_tool.context_);

    uint64_t six = 2;
    Plaintext six_plain(seal::util::uint_to_hex_string(&six, std::size_t(1)));
    Ciphertext six_encrypted;
    my_enc_tool.encryptor_->encrypt(six_plain, six_encrypted);

    Plaintext ten_plain("3");
    Ciphertext ten_encrypted;
    my_enc_tool.encryptor_->encrypt(ten_plain, ten_encrypted);

    Ciphertext six_mul_ten = six_encrypted;
    // cout << "    + noise budget in six_mul_ten: " << my_enc_tool.get_noise(six_mul_ten)
    //      << endl;

    cout << "============ " << mul_size << " ===========================" << endl;
    int i = 0;
    timer.start();
    while (mul_size > i) {
        // timer.start();
        my_enc_tool.evaluator_->multiply(six_mul_ten, ten_encrypted, six_mul_ten);
        my_enc_tool.evaluator_->relinearize_inplace(six_mul_ten, my_enc_tool.relin_key);
        // timer.stop();
        // cout << "第" << i << " 次 - "
        //      << "Time to Mul: " << timer.elapse_sec() << endl;
        // timer.clear();
        cout << "    + noise budget in six_mul_ten: " << my_enc_tool.get_noise(six_mul_ten)
             << endl;
        i++;
    }
    timer.stop();
    cout << "Time: " << timer.elapse_sec() << endl;
    cout << "=======================================" << endl;
    timer.clear();

    Plaintext decrypted_result;
    cout << "+++++++++++++++++++++++++++++++++++++" << endl;
    timer.start();
    int k = 0;
    while (mul_size > k) {
        Plaintext dec;
        my_enc_tool.decryptor_->decrypt(six_mul_ten, dec);
        k++;
    }

    timer.stop();
    cout << "Timer -> Dec : " << timer.elapse_sec() << endl;
    my_enc_tool.decryptor_->decrypt(six_mul_ten, decrypted_result);

    cout << "    + decryption: ";
    cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;
}