#pragma once

#include "merkletree.h"
#include "typedef.hpp"
#include <SEAL-4.0/seal/seal.h>
#include <assert.h>
#include <bits/stdc++.h>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string>
#include <time.h>

using namespace std;

std::map<char, std::string> table = {{'0', "0000"}, {'1', "0001"}, {'2', "0010"}, {'3', "0011"}, {'4', "0100"}, {'5', "0101"}, {'6', "0110"}, {'7', "0111"}, {'8', "1000"}, {'9', "1001"}, {'a', "1010"}, {'b', "1011"}, {'c', "1100"}, {'d', "1101"}, {'e', "1110"}, {'f', "1111"}};
/*
Transfer Function: 将sha256的值转为十进制表示
*/
string sha256_to_decimal(string s)
{
    string ans = "";
    for (auto i = 0; i < s.size(); ++i) {
        ans += table[s[i]];
    }
    return ans;
}
string my_xor(string s1, string s2)
{
    string s;
    for (auto i = 0; i < s2.size(); ++i) {
        if (s1[i] == s2[i]) {
            s.push_back('0');
        } else {
            s.push_back('1');
        }
    }
    return s;
}
const int BUFFER_SIZE = 1024;

/*
Helper function: Prints the parameters in a SEALContext.
*/
inline void print_parameters(const seal::SEALContext &context)
{
    auto &context_data = *context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme()) {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++) {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv) {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl;
}

void calSHA256(char *inp, char out_buff[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, inp, strlen(inp));
    SHA256_Final(hash, &sha256);

    // char buffx[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(out_buff + (i * 2), "%02x", hash[i]);
    }
    out_buff[65] = 0;
    // memcpy(out_buff,buffx,65);
}

std::string calSHA256(const std::string &input)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char inp[input.size() + 1];
    std::strcpy(inp, input.c_str());

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, inp, strlen(inp));
    SHA256_Final(hash, &sha256);

    char buffx[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(buffx + (i * 2), "%02x", hash[i]);
    }
    return buffx;
}

// base64编码
int Base64Encode(const char *encoded, int encodedLength, char *decoded)
{
    return EVP_EncodeBlock((unsigned char *)decoded, (const unsigned char *)encoded, encodedLength);
}

// base解码
int Base64Decode(const char *encoded, int encodedLength, char *decoded)
{
    return EVP_DecodeBlock((unsigned char *)decoded, (const unsigned char *)encoded, encodedLength);
}

// AES算法加密
std::string EncryptAES(const std::string &strKey, const std::string &strData)
{
    AES_KEY aes_key;
    if (AES_set_encrypt_key((const unsigned char *)strKey.c_str(), strKey.length(), &aes_key) < 0) {
        assert(false);
        return "";
    }

    std::string strEncryptedData;
    std::string strDataBak = strData;
    unsigned int data_length = strDataBak.length();
    int padding = 0;
    if (strDataBak.length() % AES_BLOCK_SIZE > 0) {
        padding = AES_BLOCK_SIZE - strDataBak.length() % AES_BLOCK_SIZE;
    }
    data_length += padding;
    while (padding > 0) {
        strDataBak += '\0';
        padding--;
    }
    for (unsigned int i = 0; i < data_length / AES_BLOCK_SIZE; i++) {
        std::string strBlock = strDataBak.substr(i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        unsigned char out[AES_BLOCK_SIZE];
        std::memset(out, 0, AES_BLOCK_SIZE);
        AES_encrypt((const unsigned char *)strBlock.c_str(), out, &aes_key);
        strEncryptedData += std::string((const char *)out, AES_BLOCK_SIZE);
    }

    // char buffer[BUFFER_SIZE];
    // Base64Encode(strEncryptedData.c_str(), strEncryptedData.size(), buffer);
    // return std::string(buffer, strlen(buffer));
    return strEncryptedData;
}

// AES算法解密
std::string DecryptAES(const std::string &strKey, const std::string &strDecryBase64Data)
{
    // char buffer[BUFFER_SIZE];
    // Base64Decode(strDecryBase64Data.c_str(), strDecryBase64Data.size(), buffer);
    // std::string strEncryData(buffer, strlen(buffer));
    AES_KEY aes_key;
    if (AES_set_decrypt_key((const unsigned char *)strKey.c_str(), strKey.length(), &aes_key) < 0) {
        assert(false);
        return "";
    }
    std::string strEncryData = strDecryBase64Data;
    std::string strRet;
    for (unsigned int i = 0; i < strEncryData.length() / AES_BLOCK_SIZE; i++) {
        std::string strBlock = strEncryData.substr(i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        unsigned char out[AES_BLOCK_SIZE];
        std::memset(out, 0, AES_BLOCK_SIZE);
        AES_decrypt((const unsigned char *)strBlock.c_str(), out, &aes_key);
        strRet += std::string((const char *)out, AES_BLOCK_SIZE);
    }

    std::string::size_type pos = strRet.find_last_not_of('\0');
    if (pos != std::string::npos) {
        strRet = strRet.substr(0, pos + 1);
    }
    return strRet;
}

/*
Helper function: Prints a matrix of values.
*/
template <typename T>
inline void print_matrix(std::vector<T> matrix, std::size_t row_size)
{
    /*
    We're not going to print every column of the matrix (there are 2048). Instead
    print this many slots from beginning and end of the matrix.
    */
    std::size_t print_size = 5;

    std::cout << std::endl;
    std::cout << "    [";
    for (std::size_t i = 0; i < print_size; i++) {
        std::cout << std::setw(3) << std::right << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = row_size - print_size; i < row_size; i++) {
        std::cout << std::setw(3) << matrix[i] << ((i != row_size - 1) ? "," : " ]\n");
    }
    std::cout << "    [";
    for (std::size_t i = row_size; i < row_size + print_size; i++) {
        std::cout << std::setw(3) << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = 2 * row_size - print_size; i < 2 * row_size; i++) {
        std::cout << std::setw(3) << matrix[i] << ((i != 2 * row_size - 1) ? "," : " ]\n");
    }
    std::cout << std::endl;
}

string strRand(int length)
{                  // length: 产生字符串的长度
    char tmp;      // tmp: 暂存一个随机数
    string buffer; // buffer: 保存返回值

    // 下面这两行比较重要:
    random_device rd;                   // 产生一个 std::random_device 对象 rd
    default_random_engine random(rd()); // 用 rd 初始化一个随机数发生器 random

    for (int i = 0; i < length; i++) {
        tmp = random() % 36; // 随机一个小于 36 的整数，0-9、A-Z 共 36 种字符
        if (tmp < 10) {      // 如果随机数小于 10，变换成一个阿拉伯数字的 ASCII
            tmp += '0';
        } else { // 否则，变换成一个大写字母的 ASCII
            tmp -= 10;
            tmp += 'A';
        }
        buffer += tmp;
    }
    return buffer;
}

std::string calSHA256(G1 input_number)
{
    stringstream ss;
    ss << input_number;
    string input = ss.str();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char inp[input.size() + 1];
    std::strcpy(inp, input.c_str());

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, inp, strlen(inp));
    SHA256_Final(hash, &sha256);

    char buffx[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(buffx + (i * 2), "%02x", hash[i]);
    }
    return buffx;
}

int rand_number(int n)
{
    srand((unsigned)time(NULL));
    return rand() % n;
}