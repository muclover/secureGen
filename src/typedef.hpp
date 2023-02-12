#ifndef TYPEDEF_HPP
#define TYPEDEF_HPP
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <string>

// #include <cryptopp/aes.h>
// #include <cryptopp/integer.h>
// #include <cryptopp/sha.h>
// #include <cryptopp/hex.h>
// #include <cryptopp/filters.h>
// #include <cryptopp/modes.h>
// #include <cryptopp/base64.h>

typedef libff::alt_bn128_pp ppT;
typedef libff::Fr<ppT> FieldT;
typedef libff::G1<ppT> G1;
typedef libff::G2<ppT> G2;

typedef unsigned __int128 u128;
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;

typedef __int128 i128;
typedef long long i64;
typedef int i32;
typedef char i8;

#endif // TYPEDEF_HPP
