#pragma once

#include "role.hpp"
#include "typedef.hpp"
#include "util.hpp"
#include <iostream>
#include <string>
#include <vector>

/* SEAL HE */
void gen_encryption_params(std::uint64_t N,             // degree of polynomial
                           std::uint32_t plain_modulus, // bits of plaintext coefficient
                           seal::EncryptionParameters &enc_params)
{
    enc_params.set_poly_modulus_degree(N); //8196 32768
    enc_params.set_coeff_modulus(seal::CoeffModulus::BFVDefault(N));
    // enc_params.set_plain_modulus(seal::PlainModulus::Batching(N, logt + 1));
    enc_params.set_plain_modulus(plain_modulus); // 786433
}

class Encryptor_Help {
public:
    // Encryptor_Help(std::uint32_t N, std::uint32_t logt, seal::EncryptionParameters &enc_params)
    // {
    //     gen_encryption_params(N, logt, enc_params);
    // }

    Encryptor_Help(const seal::EncryptionParameters &enc_params) :
        enc_params_(enc_params)
    {
        // context_ = make_shared<seal::SEALContext>(enc_params, true);
        context_ = make_shared<seal::SEALContext>(enc_params);
        // print_parameters(*context_);
        keygen_ = make_unique<seal::KeyGenerator>(*context_);
        secret_key = keygen_->secret_key();
        keygen_->create_public_key(public_key);
        keygen_->create_relin_keys(relin_key);

        // seal::PublicKey public_key;
        // keygen_->create_public_key(public_key);
        // seal::SecretKey secret_key = keygen_->secret_key();

        // encryptor_ = make_unique<seal::Encryptor>(*context_, secret_key);
        encryptor_ = make_unique<seal::Encryptor>(*context_, public_key);
        decryptor_ = make_unique<seal::Decryptor>(*context_, secret_key);
        evaluator_ = make_unique<seal::Evaluator>(*context_);
        // encoder_ = make_unique<seal::BatchEncoder>(*context_);
    }
    int get_noise(const seal::Ciphertext &encrypted)
    {
        return decryptor_->invariant_noise_budget(encrypted);
    }

public:
    seal::SecretKey secret_key;
    seal::PublicKey public_key;
    seal::RelinKeys relin_key;

    // private:
    seal::EncryptionParameters enc_params_;
    std::shared_ptr<seal::SEALContext> context_;
    std::unique_ptr<seal::KeyGenerator> keygen_;
    std::unique_ptr<seal::Encryptor> encryptor_;
    std::unique_ptr<seal::Decryptor> decryptor_;
    std::unique_ptr<seal::Evaluator> evaluator_;
    std::unique_ptr<seal::BatchEncoder> encoder_;
};

/* Merkle Tree*/
merkletree MTree(const std::vector<string> &x)
{
    vector<char *> leaves_open(x.size());
    for (auto i = 0; i < leaves_open.size(); i++) {
        leaves_open[i] = new char[65];
    }

    //  计算节点的哈希
    for (auto i = 0; i < leaves_open.size(); i++) {
        strcpy(leaves_open[i], calSHA256(x[i]).c_str());
    }

    // 构建 merkle tree
    merkletree mtree = merkletree(leaves_open);

    for (auto i = 0; i < leaves_open.size(); i++) {
        delete leaves_open[i];
    }

    // char *root_MTstar = mtree.root();
    // for (auto i = 0; i < mtree.size(); i++) {
    //     cout << mtree.tree[i] << endl;
    // }

    return mtree;
}

std::vector<ProofNode> MTProof(merkletree &MT, std::string &s)
{
    s = calSHA256(s);
    return MT.proof((char *)s.c_str());
}
bool MTVerif(char *root, const string &leaf, vector<ProofNode> proof)
{
    return verifyProof((char *)leaf.c_str(), root, proof);
}

std::string PRF(std::string s, std::string value)
{
    return calSHA256(s + value);
}

struct Service_info {
    G1 generator;
    int p;
    BIL bil; // size: p
    int k;
    BIL bbi; // basic 10

    merkletree MT_star; // basic open

    G1 tau_key;
    std::string HFSK;
    seal::Ciphertext c;
    std::string H_s_3;

    uint64_t s;
    uint64_t r;
    merkletree MTS; // bil
    seal::Ciphertext c_par;
    std::vector<G1> tau_groups;

    std::string H_s_2;
    merkletree MTS_par; // bil
    FieldT ri;
    G1 gr;
    std::string R;

    merkletree MTC;
    std::string H_s_1;
    // RSA 加密密文 C
    std::vector<std::string> C;

    // index
    int gamma;
};

void setup(Service_info &service_info)
{
    int p = 100;
    BIL bil(p, "none");
    int k = 10;
    BIL bbi(k, "result");

    service_info.generator = G1::random_element();
    service_info.k = k;
    service_info.p = p;
    service_info.bbi = bbi;
    service_info.bil = bil;

    // for (int i = 0; i < k; i++) {
    //     // std::cout << bbi.biolabels[i].biological << " -- " << bbi.biolabels[i].value << "\n";
    //     std::cout << bil.biolabels[i].biological << " -- " << bil.biolabels[i].value << "\n";
    // }
    // 产生 generator g
    // 产生两个哈希函数和 PRF
    // 定义测试结果 key-value pair

    // map<string, string> M_result;

    // M -> {BIL,value}
    //      BIL = {biolbael_1,\dots,boilabel_p}
    // 设置 Timeout_1, Timeout_2, Timeout_3
}

void user_register(Service_info &service_info, Server &server, Client &client)
{
    // S
    // 1. 产生身份信息 I_j
    // 2. G 验证信息，并产生对应的 sk pk
    FieldT sk_server = FieldT::random_element();
    G1 pk_server = sk_server * service_info.generator;
    // 3. G 发布公钥和身份信息到区块链中
    // Server server(sk_server, pk_server);
    server = Server(sk_server, pk_server);

    // C
    // 1. 发送个人基本生物信息 BBI*
    int basic_bio_size = service_info.k;
    BIL bbi = service_info.bbi;
    // 2. 用户提供个人身份信息
    FieldT sk_client = FieldT::random_element();
    G1 pk_client = sk_client * service_info.generator;
    vector<string> ds(basic_bio_size);
    // cout << "++++++++++++++++++++++++++++++++++++" << endl;
    // for (int i = 0; i < basic_bio_size; i++) {
    //     ds[i] = strRand(100);
    //     cout << ds[i] << endl;
    // }
    // cout << "++++++++++++++++++++++++++++++++++++" << endl;

    // 3. G 验证信息产生 sk pk
    // 4. G 产生承诺 C(H(bio|val)) 和承诺 open 值的Merkle Tree MT*
    vector<string> H_bio_val(basic_bio_size);
    // cal Hash(bio|val)
    for (int i = 0; i < basic_bio_size; i++) {
        H_bio_val[i] = calSHA256(bbi.biolabels[i].biological + bbi.biolabels[i].value);
        // string s = calSHA256(bbi.biolabels[i].biological + bbi.biolabels[i].value);
        // H_bio_val[i] = s;
    }

    vector<string> com(basic_bio_size);
    // cal Com(H(bio|val)) = H(H(bio|val) | ds)
    for (int i = 0; i < basic_bio_size; i++) {
        com[i] = calSHA256(H_bio_val[i] + ds[i]);
    }

    client = Client(sk_client, pk_client, bbi, com, ds);

    // generate MT*
    // 1. 构建 Merkle Tree
    service_info.MT_star = MTree(ds);
}

seal::Plaintext encode_hash_to_plaintext(std::string s)
{
    // "7FFx^3 + 1x^1 + 3"
    std::string res;
    // std::cout << "encoder hash to plaintext : " << s << endl;
    for (int i = s.size() - 1; i > 0; i--) {
        res += s[i];
        res += "x^" + to_string(i) + " + ";
    }
    res += s[0];
    // std::cout << "res: " << res << std::endl;
    return seal::Plaintext(res);
}

// N is a group of people
seal::Ciphertext service_request(Service_info &service_info, Server &server, Client &client, Encryptor_Help &encryptor_tool)
{
    // 初始化同态加密参数(pk,sk)
    // 哈希 sk
    stringstream FHE_sk_stream;
    encryptor_tool.secret_key.save(FHE_sk_stream);
    string HFSK = calSHA256(FHE_sk_stream.str());
    service_info.HFSK = HFSK;

    // 计算 \tau = pk ^ x
    G1 tau_key = client.get_sk() * server.pk;

    //计算密文 c= Enc(H(\tau))
    string H_tau = calSHA256(tau_key);
    seal::Plaintext p_tau = encode_hash_to_plaintext(H_tau);
    seal::Ciphertext c_tau;
    encryptor_tool.encryptor_->encrypt(p_tau, c_tau);

    service_info.c = c_tau;

    return c_tau;
}

seal::Ciphertext service_confirm(Service_info &service_info, const Server &server, Encryptor_Help &enc_tool)
{
    // 1. 计算一群用户的 tau
    std::vector<G1> taus(service_info.tau_groups.size());
    for (int i = 0; i < taus.size(); i++) {
        taus[i] = server.get_sk() * service_info.tau_groups[i];
    }

    // 2. 生成随机数
    uint64_t s = (uint64_t)rand_number(100);
    uint64_t r = (uint64_t)rand_number(100) + 10;
    service_info.s = s;
    service_info.r = r;

    // 3. hash s 3 times
    std::string H_s_3 = calSHA256(calSHA256(calSHA256(std::to_string(s))));
    service_info.H_s_3 = H_s_3;

    // 4. 计算所有的 PRF_s(H(bio)) = H(H(bio)|s)
    std::vector<std::string> nodes(service_info.bil.biolabels.size());
    for (auto i = 0; i < nodes.size(); i++) {
        nodes[i] = PRF(to_string(s), calSHA256(service_info.bil.biolabels[i].biological));
    }

    // 5. 构建 Merkle Tree
    merkletree MTS = MTree(nodes);
    service_info.MTS = MTS;

    // 6. 计算 c'= Enc(r * \sum{(H_0(\tau_i)-c)} +s)
    seal::Plaintext r_plain(seal::util::uint_to_hex_string(&r, std::size_t(1)));
    seal::Plaintext s_plain(seal::util::uint_to_hex_string(&s, std::size_t(1)));
    std::cout << __LINE__ << "s_plain : 0x" << s_plain.to_string() << std::endl;

    std::vector<seal::Plaintext> taus_plain(taus.size());
    for (auto i = 0; i < taus_plain.size(); i++) {
        taus_plain[i] = encode_hash_to_plaintext(calSHA256(taus[i]));
    }

    seal::Ciphertext c_par;
    std::vector<seal::Ciphertext> c_tmps(taus_plain.size());

    for (auto i = 0; i < taus_plain.size(); i++) {
        // taus_plain[i] = encode_hash_to_plaintext(calSHA256(taus[i]));
        c_tmps[i] = service_info.c;
        enc_tool.evaluator_->sub_plain_inplace(c_tmps[i], taus_plain[i]);
    }

    c_par = c_tmps[0];

    std::cout << "------- Begin ----------------" << std::endl;
    std::cout << "Noise: " << enc_tool.decryptor_->invariant_noise_budget(c_par) << std::endl;
    std::cout << "-----------------------" << std::endl;

    for (auto i = 1; i < c_tmps.size(); i++) {
        enc_tool.evaluator_->multiply_inplace(c_par, c_tmps[i]);
        enc_tool.evaluator_->relinearize_inplace(c_par, enc_tool.relin_key);
    }

    std::cout << "------- Sum of taus ----------------" << std::endl;
    std::cout << "Noise: " << enc_tool.decryptor_->invariant_noise_budget(c_par) << std::endl;
    std::cout << "-----------------------" << std::endl;

    enc_tool.evaluator_->multiply_plain_inplace(c_par, r_plain);
    enc_tool.evaluator_->relinearize_inplace(c_par, enc_tool.relin_key);
    enc_tool.evaluator_->add_plain_inplace(c_par, s_plain);

    std::cout << "---------- END -------------" << std::endl;
    std::cout << "Noise: " << enc_tool.decryptor_->invariant_noise_budget(c_par) << std::endl;
    std::cout << "-----------------------" << std::endl;
    service_info.c_par = c_par;

    return c_par;
}

void sample_submit(Service_info &service_info, Server &server, Encryptor_Help &enc_tool)
{
    // 1. 解密 c' 得到 s
    seal::Plaintext plain_c_par;
    enc_tool.decryptor_->decrypt(service_info.c_par, plain_c_par);
    auto p_s_hex = plain_c_par.to_string(); // hex
    // auto p_s_dec = seal::util::hex_string_to_uint(p_s_hex, );
    uint64_t p_s_dec = 0;
    // hex to dec
    seal::util::hex_string_to_uint(p_s_hex.c_str(), p_s_hex.size(), std::size_t(1), &p_s_dec);
    std::cout << "sample submit: "
              << "plaintext_s : " << p_s_dec << std::endl;

    // 2. 哈希 s 两次
    auto p_s = std::to_string(p_s_dec);

    string H_s_2 = calSHA256(calSHA256(p_s));
    service_info.H_s_2 = H_s_2;

    // 3. 构造 BIL MT
    std::vector<std::string> nodes(service_info.bil.biolabels.size());
    for (auto i = 0; i < nodes.size(); i++) {
        // nodes[i] = calSHA256(calSHA256(H_s_3) + std::to_string(s));
        nodes[i] = PRF(p_s, calSHA256(service_info.bil.biolabels[i].biological));
    }

    // 5. 构建 Merkle Tree
    merkletree MTS_par = MTree(nodes);
    service_info.MTS_par = MTS_par;

    if (calSHA256(H_s_2) != service_info.H_s_3) {
        std::cout << "H_s_2 != H_s_3" << std::endl;
        throw "Terminate the service request";
        exit(0);
    }

    // 收集用户信息，产生 ID
    std::vector<std::string> IDs;
    for (int i = 0; i < service_info.tau_groups.size(); i++) {
        IDs.push_back(std::to_string(i) + "ID");
    }

    FieldT ri = FieldT::random_element();
    service_info.ri = ri;
    G1 gr = ri * service_info.generator;
    service_info.gr = gr;

    // R=ID ⊕ H_0(gr)
    string H_0_xr_binary = sha256_to_decimal(calSHA256(ri * server.pk));
    string ID_xr = sha256_to_decimal(calSHA256(IDs[0]));
    string R = my_xor(H_0_xr_binary, ID_xr);
    service_info.R = R;
}

void result_upload(Service_info &service_info)
{
    // 创建测试结果
    BIL M_result(service_info.p, "result");
    std::vector<std::string> C;

    //密钥为PRF_s(biolabel)
    vector<string> C_AES_base64(M_result.biolabels.size());
    for (auto i = 0; i < C_AES_base64.size(); i++) {
        //密钥长度要求为128，192，256字节,并且不可为空
        string strKey = sha256_to_decimal(PRF(to_string(service_info.s), M_result.biolabels[i].biological));

        string strOriginData = M_result.biolabels[i].value;
        string strEncryBase64Data = EncryptAES(strKey, strOriginData);
        C_AES_base64[i] = strEncryBase64Data;
    }
    // cout << "测试结果" << endl;
    // for (auto i = 0; i < C_AES_base64.size(); ++i) {
    //     cout << C_AES_base64[i] << endl;
    // }

    //构造密文的MT树
    cout << "----------- MerkleTree C --------------------" << endl;
    vector<char *> leaves_C(C_AES_base64.size());
    for (auto i = 0; i < leaves_C.size(); i++) {
        leaves_C[i] = new char[65];
    }
    for (auto i = 0; i < leaves_C.size(); i++) {
        strcpy(leaves_C[i], calSHA256(C_AES_base64[i]).c_str());
    }

    merkletree MT_C = merkletree(leaves_C);
    service_info.MTC = MT_C;
    std::string H_s_1 = calSHA256(to_string(service_info.s));
    service_info.H_s_1 = H_s_1;

    service_info.C = C_AES_base64;
}

void result_dispute(Service_info &info, Client &client)
{
    int k = 1;

    std::vector<std::string> M_dec_result(info.C.size());
    for (auto i = 0; i < M_dec_result.size(); i++) {
        std::string strKey = sha256_to_decimal(PRF(to_string(info.s), info.bil.biolabels[i].biological));
        M_dec_result[i] = DecryptAES(strKey, info.C[i]);
    }

    // 比较 M_result 和 basic 信息中是否存在不相等的情况
    // for simplify, we only consider 前 10 个元素
    M_dec_result[info.C.size() - 1] = "error";
    for (auto i = 0; i < client.BBI.biolabels.size(); i++) {
        if (M_dec_result[i] != client.BBI.biolabels[i].value) {
            std::cout << " M_result not equal to BBI"
                      << "\n";
            k = i;
        }
    }

    info.gamma = k;

    // cout << "------------------MT star-----------------" << endl;
    auto MT_star = info.MT_star;
    std::string dispute_node = client.ds[k];
    // cout << "++++++++++++ client ++++++++++++++" << endl;
    // cout << "ds[" << k << "]" << client.ds[k] << endl;
    // cout << "++++++++++++ client ++++++++++++++" << endl;

    auto MT_star_proof_node = MTProof(MT_star, dispute_node);
    auto verify = MTVerif(MT_star.root(), dispute_node, MT_star_proof_node);
    cout << "Dispute verify result: " << verify << endl;
    // for (int i = 0; i < MT_star.tree.size(); i++) {
    //     cout << "MT_star: " << i << ": " << MT_star.tree[i] << endl;
    // }

    // for (auto i = 0; i < M_dec_result.size(); ++i) {
    //     cout << M_dec_result[i] << endl;
    // }
    // cout << "-------basic result-----------" << endl;
    // for (auto i = 0; i < info.k; i++) {
    //     cout << info.bbi.biolabels[i].value << endl;
    // }
}

void self_prove(Service_info &info)
{
    int gamma = info.gamma;
    cout << "gamma: " << gamma << endl;

    auto bio_gamma = PRF(std::to_string(info.s), calSHA256(info.bil.biolabels[gamma].biological));

    auto MTS_proof_gamma = MTProof(info.MTS, bio_gamma);

    auto C_gamma = info.C[gamma];
    auto MTC_proof_gamma = MTProof(info.MTC, C_gamma);

    auto verify_S = MTVerif(info.MTS.root(), bio_gamma, MTS_proof_gamma);
    auto verify_C = MTVerif(info.MTC.root(), C_gamma, MTC_proof_gamma);

    cout << "MTS - verify: " << verify_S << endl;
    cout << "MTC - verify: " << verify_C << endl;
}