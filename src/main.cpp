#include "merkletree.h"
#include "role.hpp"
#include "timer.hpp"
#include "util.hpp"
#include <SEAL-4.0/seal/seal.h>
#include <fstream>
#include <iostream>
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <map>
#include <random>
using namespace std;
using namespace seal;

string setup_FHE(string s)
{
    string a = "";
    for (auto i = 0; i < 2; i++) {
    }
    return a;
}

vector<uint64_t> &get_batch_array(vector<uint64_t> &matrix, string &s)
{
    for (int i = 0; i < s.size(); i++) {
        matrix[i] = (uint64_t)(s[i] - '0');
    }
    return matrix;
}

int main()
{
    //保存时间参数
    map<string, double> running_time;
    Timer timer0;
    Timer timer1;

    timer0.start();
    ppT::init_public_params();
    G1 g = G1::random_element(); // public parameter

    // 1. 注册
    timer1.start();
    FieldT sk_sp = FieldT::random_element();
    service_provider sp(sk_sp, g);
    FieldT sk_user = FieldT::random_element();
    generic_user user(sk_user, g);
    //生成BIL
    int BIL_size = 1000000;
    vector<string> BIL;
    for (auto i = 0; i < user.BBI.size(); ++i) {
        BIL.push_back(user.BBI[i].biological);
    }

    for (auto i = user.BBI.size(); i < BIL_size; ++i) {
        BIL.push_back(strRand(100));
    }
    timer1.stop();
    running_time["1.register time: "] = timer1.elapse_sec();
    timer1.clear();

    // 2. 产生commit和MTree
    timer1.start();
    vector<string> commit_basic_biological(user.BBI.size());
    vector<string> d(user.BBI.size());
    for (auto i = 0; i < d.size(); ++i) {
        d[i] = strRand(100);
    }
    for (auto i = 0; i < commit_basic_biological.size(); i++) {
        commit_basic_biological[i] = calSHA256(user.BBI[i].biological + user.BBI[i].value + d[i]);
    }

    cout << "----------- MerkleTree* --------------------" << endl;
    vector<char *> leaves_open(d.size());
    for (auto i = 0; i < leaves_open.size(); i++) {
        leaves_open[i] = new char[65];
    }

    // initialize merkletree MT*
    for (auto i = 0; i < leaves_open.size(); i++) {
        // strcpy(leaves_open[i],calSHA256(user.BBI[i].biological+user.BBI[i].value+d[i]).c_str());
        // open 值的MT
        strcpy(leaves_open[i], calSHA256(d[i]).c_str());
    }
    cout << "Mtree * " << endl;
    merkletree mtree_star = merkletree(leaves_open);
    char *root_MTstar = mtree_star.root();
    for (auto i = 0; i < mtree_star.size(); i++) {
        cout << mtree_star.tree[i] << endl;
    }
    timer1.stop();

    running_time["2.generate commitment time: "] = timer1.elapse_sec();

    timer1.clear();

    // 3. 发起request
    // user使用多个pk
    timer1.start();
    const int N = 20;
    vector<G1> public_key_group(N);
    public_key_group[0] = user.pk; //用户公钥包含在N中
    for (auto i = 1; i < public_key_group.size(); i++) {
        public_key_group[i] = G1::random_element();
    }
    /*
            +----------------------------------------------------+
            | poly_modulus_degree | max coeff_modulus bit-length |
            +---------------------+------------------------------+
            | 1024                | 27                           |
            | 2048                | 54                           |
            | 4096                | 109                          |
            | 8192                | 218                          |
            | 16384               | 438                          |
            | 32768               | 881                          |
            +---------------------+------------------------------+
    */
    //全同态初始化

    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768; // 8192 16384 32768
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    print_parameters(context);
    auto qualifiers = context.first_context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    BatchEncoder batch_encoder(context);

    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    stringstream FHE_sk_stream;
    secret_key.save(FHE_sk_stream);
    // SecretKey sk;
    // sk.load(context, FHE_sk_stream);
    // cout <<"************"<<endl;
    // cout << FHE_sk_stream.str()<<endl;
    string HFSK = calSHA256(FHE_sk_stream.str());
    G1 tau_key = user.getkey() * sp.pk;

    string H_tau = calSHA256(tau_key);
    //加密 c=FHE(H_o(tau))
    vector<uint64_t> c_matrix(slot_count, 0ULL);
    get_batch_array(c_matrix, H_tau);
    Plaintext c_plain;
    batch_encoder.encode(c_matrix, c_plain);

    Ciphertext c_encrypted;
    encryptor.encrypt(c_plain, c_encrypted);

    timer1.stop();
    running_time["3.request time: "] = timer1.elapse_sec();

    timer1.clear();

    // 4. confirm
    //产生所有pk的tau
    timer1.start();
    vector<G1> tau_group(N);
    vector<string> tau_group_hash(N);
    for (auto i = 0; i < N; i++) {
        tau_group[i] = sp.getkey() * public_key_group[i];
        tau_group_hash[i] = calSHA256(tau_group[i]);
    }

    // int s = 155, r = 10;
    FieldT s1 = FieldT::random_element();
    FieldT r1 = FieldT::random_element();
    stringstream f_to_s;
    f_to_s << s1;
    string s = f_to_s.str();
    f_to_s.str("");
    f_to_s << r1;
    string r = f_to_s.str();
    f_to_s.str("");
    cout << "s = " << s << endl;
    cout << "r = " << r << endl;
    string H_s_3 = calSHA256(calSHA256(calSHA256(s)));
    cout << "H_s_3: " << H_s_3 << endl;
    cout << "----------- MerkleTree s --------------------" << endl;
    vector<char *> leaves_BIL(BIL.size());
    for (auto i = 0; i < leaves_BIL.size(); i++) {
        leaves_BIL[i] = new char[65];
    }
    // PRF_x(H) = H(H(bio)||s)
    for (auto i = 0; i < leaves_BIL.size(); i++) {
        strcpy(leaves_BIL[i], calSHA256(calSHA256(BIL[i]) + s).c_str());
    }

    merkletree MTs = merkletree(leaves_BIL);
    char *root_MTs = MTs.root();
    // for (auto i = 0; i < MTs.size(); i++) {
    //     cout << MTs.tree[i] << endl;
    // }
    cout << leaves_BIL.size() << endl;
    //计算c'
    Ciphertext c_encrypted_2(c_encrypted);
    vector<Plaintext> c_plain_group(N);
    //计算group的plaintext
    for (auto i = 0; i < c_plain_group.size(); ++i) {
        vector<uint64_t> tau_group_matrix(slot_count, 0ULL);
        get_batch_array(tau_group_matrix, tau_group_hash[i]);
        batch_encoder.encode(tau_group_matrix, c_plain_group[i]);
    }

    evaluator.sub_plain_inplace(c_encrypted_2, c_plain_group[0]);
    cout << "    + noise budget in hash_c_0 初始化: " << decryptor.invariant_noise_budget(c_encrypted_2) << " bits"
         << endl;
    Plaintext decrypted_result;

    for (auto i = 1; i < tau_group_hash.size(); i++) {
        Ciphertext c_encrypted_temp = c_encrypted;

        evaluator.sub_plain_inplace(c_encrypted_temp, c_plain_group[i]);
        evaluator.multiply_inplace(c_encrypted_2, c_encrypted_temp);
        evaluator.relinearize_inplace(c_encrypted_2, relin_keys);
    }
    cout << "    + Noise budget in encrypted_matrix 累乘之后 : " << decryptor.invariant_noise_budget(c_encrypted_2)
         << "        bits " << endl;
    // Plaintext r_plain(to_string(r));
    vector<uint64_t> s_matrix(slot_count, 0ULL);
    vector<uint64_t> r_matrix(slot_count, 0ULL);
    Plaintext s_matrix_plain;
    Plaintext r_matrix_plain;
    get_batch_array(s_matrix, s);
    get_batch_array(r_matrix, r);
    batch_encoder.encode(s_matrix, s_matrix_plain);
    batch_encoder.encode(r_matrix, r_matrix_plain);

    evaluator.multiply_plain_inplace(c_encrypted_2, r_matrix_plain);
    evaluator.add_plain_inplace(c_encrypted_2, s_matrix_plain);
    cout << "    + Noise budget in encrypted_matrix 乘以r加上s之后 : "
         << decryptor.invariant_noise_budget(c_encrypted_2) << "        bits " << endl;
    decryptor.decrypt(c_encrypted_2, decrypted_result);
    vector<uint64_t> c_result;
    batch_encoder.decode(decrypted_result, c_result);

    cout << "解密矩阵" << endl;
    for (int i = 0; i < 256; i++) {
        cout << c_result[i];
    }
    cout << endl;
    cout << "    + noise budget in c_encrypted_2: " << decryptor.invariant_noise_budget(c_encrypted_2) << " bits"
         << endl;

    timer1.stop();
    running_time["4.confirm time: "] = timer1.elapse_sec();
    timer1.clear();

    // 5. submit
    //解密c'得到s
    timer1.start();
    cout << "-------------------------------------------------" << endl;
    for (auto i = 0; i < s.size(); ++i) {
        f_to_s << c_result[i];
    }
    string s_;
    f_to_s >> s_;
    f_to_s.str("");
    cout << "s_: " << s_ << endl;
    cout << "s_: " << s_.size() << endl;
    string H_s_2 = calSHA256(calSHA256(s_));

    cout << "----------- MerkleTree s' --------------------" << endl;
    // PRF_x(H) = H(H(bio)||s)
    for (auto i = 0; i < leaves_BIL.size(); i++) {
        strcpy(leaves_BIL[i], calSHA256(calSHA256(BIL[i]) + s_).c_str());
    }

    merkletree MTs_ = merkletree(leaves_BIL);
    char *root_MTs_ = MTs_.root();
    // for (auto i = 0; i < MTs_.size(); i++) {
    //     cout << MTs_.tree[i] << endl;
    // }
    cout << "s' size :" << leaves_BIL.size() << endl;
    if (calSHA256(H_s_2) != H_s_3 || root_MTs != root_MTs) {
        cout << "------------" << endl;
        cout << "abort" << endl;
        cout << "-----------" << endl;
        assert(calSHA256(H_s_2) == H_s_3);
    }

    //收集u的信息产生ID
    FieldT r_number = FieldT::random_element();
    G1 gr = r_number * g;
    string H_0_xr = calSHA256(r_number * sp.pk);
    string ID = calSHA256("user name ID");
    // R=ID ⊕ H_0(gr)
    string H_0_xr_binary = sha256_to_decimal(H_0_xr);
    string ID_xr = sha256_to_decimal(ID);
    string R = my_xor(H_0_xr_binary, ID_xr);
    // cout << "H_0: " << H_0_xr_binary << endl;
    // cout << "---------------" << endl;
    // cout << "ID: " << ID_xr << endl;
    // cout << "---------------" << endl;
    cout << "R: " << R << "---------------" << endl;

    timer1.stop();
    running_time["5.submit time: "] = timer1.elapse_sec();
    timer1.clear();

    // 6. result upload
    timer1.start();
    vector<string> M_test_result(BIL.size());
    for (auto i = 0; i < user.BBI.size(); ++i) {
        M_test_result[i] = user.BBI[i].value;
        // cout << M_test_result[i] << endl;
    }
    for (auto i = user.BBI.size(); i < M_test_result.size(); ++i) {
        M_test_result[i] = strRand(30);
    }
    // M_test_result[3] = strRand(30);

    vector<basic_biological> M(BIL.size());
    for (auto i = 0; i < M.size(); i++) {
        M[i].biological = BIL[i];
        M[i].value = M_test_result[i];
    }
    //产生结果的密文
    //密钥为PRF_s(biolabel)
    vector<string> C_AES_base64(BIL.size());
    for (auto i = 0; i < BIL.size(); i++) {
        //密钥长度要求为128，192，256字节,并且不可为空
        string strKey = sha256_to_decimal(calSHA256(BIL[i] + s));

        // cout <<"**key**"<<strKey<<""<<endl;
        // cout << strKey.size() << endl;
        string strOriginData = M[i].value;
        string strEncryBase64Data = EncryptAES(strKey, strOriginData);
        C_AES_base64[i] = strEncryBase64Data;
    }
    cout << "测试结果" << endl;
    for (auto i = 0; i < user.BBI.size(); ++i) {
        cout << C_AES_base64[i] << endl;
    }
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
    char *root_MT_C = MT_C.root();
    // for (auto i = 0; i < MT_C.size(); i++) {
    //     cout << MT_C.tree[i] << endl;
    // }
    cout << "C size: " << leaves_C.size() << endl;
    string H_s_1 = calSHA256(s);
    timer1.stop();
    running_time["6.result upload time: "] = timer1.elapse_sec();

    timer1.clear();

    // 7. result dispute
    //解密得到结果

    timer1.start();
    vector<string> M_dec_result(C_AES_base64.size());
    for (auto i = 0; i < BIL.size(); i++) {
        string strKey = sha256_to_decimal(calSHA256(BIL[i] + s));
        M_dec_result[i] = DecryptAES(strKey, C_AES_base64[i]);
    }

    cout << "解密结果" << endl;
    for (auto i = 0; i < user.BBI.size(); ++i) {
        cout << M_dec_result[i] << endl;
    }
    //将结果与基本信息进行比对
    bool compare_result = true;
    int k = 0;
    for (auto i = 0; i < user.BBI.size(); i++) {
        if (M_dec_result[i] != user.BBI[i].value) {
            compare_result = false;
            k = i;
        }
        cout << "M_dec_result " << i << ":  " << M_dec_result[i] << endl;
        cout << "user.BBI " << i << "  :" << user.BBI[i].value << endl;
    }

    //发现信息错误，发起dispute
    if (!compare_result) {
        cout << "************----------DISPUTE PHRASE-------**************************" << endl;
    } else {
        cout << "__________________________TRUE 正确_________________________000000000000000000";
        cout << "=============================================================" << endl;
    }
    //产生错误信息节点在 c* 数中的Merkle proof
    char *sample_leaf_open_k = leaves_open[k];
    vector<ProofNode> mtree_star_proof = mtree_star.proof(sample_leaf_open_k);

    // verify proof
    bool verified_MT_star = verifyProof(sample_leaf_open_k, root_MTstar, mtree_star_proof);
    cout << "Mtree * verified status: " << verified_MT_star << endl;
    timer1.stop();
    running_time["7.dispute time: "] = timer1.elapse_sec();
    timer1.clear();

    // 8. self-prove
    //发现错误信息节点在BIL中对应的位置gamma
    timer1.start();
    int gamma = 0;
    for (auto i = 0; i < BIL.size(); i++) {
        if (user.BBI[k].biological == BIL[i]) {
            gamma = i;
        }
    }
    cout << "gamma : " << gamma << endl;
    cout << "k : " << k << endl;

    //产生gamma处的Merkle proof 分别在 MT_s MT_C
    char *sample_leaf_MTs = leaves_BIL[gamma];
    vector<ProofNode> mtree_s_proof = MTs.proof(sample_leaf_MTs);
    // verify proof
    bool verified_MT_s = verifyProof(sample_leaf_MTs, root_MTs, mtree_s_proof);
    cout << "Mtree S verified status: " << verified_MT_s << endl;

    char *sample_leaf_MTc = leaves_C[gamma];
    vector<ProofNode> mtree_c_proof = MT_C.proof(sample_leaf_MTc);
    // verify proof
    bool verified_MT_c = verifyProof(sample_leaf_MTc, root_MT_C, mtree_c_proof);
    cout << "Mtree C verified status: " << verified_MT_c << endl;
    timer1.stop();
    running_time["8.self prove time: "] = timer1.elapse_sec();

    timer0.stop();
    running_time["总时间:"] = timer0.elapse_sec();

    for (auto it : running_time) {
        cout << it.first << it.second << " s " << endl;
    }

    // save running time
    ofstream out("out.txt");
    out << "**************  用户个数:" << N << "****************" << endl;
    out << "**************  测试结果数量:" << BIL.size() << "****************" << endl;
    out << "**************  基本信息个数:" << user.BBI.size() << "****************" << endl;
    for (auto it : running_time) {
        out << it.first << it.second << "s" << endl;
    }
    // for (map<string, double>::iterator iter = running_time.begin(); iter != running_time.end(); ++iter) {
    //     cout << iter->first << iter->second << " s " << endl;
    // }
    out.close();
    return 0;
}

// //密钥长度要求为128，192，256字节,并且不可为空
// string strKey = "encrypted_123456";
// string strOriginData = "encry12345_";
// string strEncryBase64Data = EncryptAES(strKey, strOriginData);
// string strDecryBase64Data = DecryptAES(strKey, strEncryBase64Data);
// cout << "OriginData:\t\t" << strOriginData << endl;
// cout << "EncryBase64Data:\t" << strEncryBase64Data << endl;
// cout << "DecryBase64Data:\t" << strDecryBase64Data << endl;
