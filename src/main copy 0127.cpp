#include <iostream>

#include <seal/seal.h>
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <map>
#include "merkletree.h"
#include "role.hpp"
#include "timer.hpp"
using namespace std;
using namespace seal;
std::string calSHA256(G1 input_number) {
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

string setup_FHE(string s) {
    string a = "";
    for (auto i = 0; i < 2; i++) {
    }
    return a;
}

map<string, double> running_time;

int main() {
    timer timer0;
    timer timer1;

    timer0.start();
    ppT::init_public_params();
    G1 g = G1::random_element(); // public parameter

    cout << "hello1" << endl;
    // 1. 注册
    timer1.start();
    FieldT sk_sp = FieldT::random_element();
    // cout <<"hello2"<<endl;
    service_provider sp(sk_sp, g);
    FieldT sk_user = FieldT::random_element();
    generic_user user(sk_user, g);
    // cout << user.BBI[0].value<<endl;

    timer1.stop();
    running_time["1.register time: "] = timer1.elapse_sec();
    timer1.clear();
    // 2. 产生commit和MTree
    timer1.start();
    vector<string> commit_basic_biological(user.BBI.size());
    vector<string> d = {"10", "11", "12"};
    for (auto i = 0; i < commit_basic_biological.size(); i++) {
        commit_basic_biological[i] = calSHA256(user.BBI[i].biological + user.BBI[i].value + d[i]);
        // cout <<commit_basic_biological[i]<<endl;
    }
    cout << "----------- MerkleTree* --------------------" << endl;
    vector<char *> leaves_open(3);
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
    const int N = 5;
    vector<G1> public_key_group(N);
    public_key_group[0] = user.pk; //用户公钥包含在N中
    for (auto i = 1; i < public_key_group.size(); i++) {
        public_key_group[i] = G1::random_element();
    }

    //全同态初始化
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
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

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    stringstream FHE_sk_stream;
    secret_key.save(FHE_sk_stream);
    // SecretKey sk;
    // sk.load(context, FHE_sk_stream);
    // cout <<"************"<<endl;
    // cout << FHE_sk_stream.str()<<endl;
    string HFSK = calSHA256(FHE_sk_stream.str());
    G1 tau_key = user.getkey() * sp.pk;

    string H_tau = calSHA256(tau_key);
    cout << "******************" << endl;
    int range_number = 10;
    //加密 c=FHE(H_o(tau))
    cout << H_tau << endl;
    Plaintext c_plain(H_tau.substr(0, range_number));
    Ciphertext c_encrypted;
    encryptor.encrypt(c_plain, c_encrypted);
    cout << "Plain::: " << c_plain.to_string() << endl;
    // Plaintext c_plain;
    // batch_encoder.encode(matrix1, c_plain);
    // encryptor.encrypt(c_plain, c_encrypted);

    timer1.stop();
    running_time["3.request time: "] = timer1.elapse_sec();

    timer1.clear();

    // 4. confirm
    //产生所有pk的tau
    timer1.start();
    vector<G1> tau_group(N);
    vector<string> tau_group_hash(N);
    vector<string> tau_group_hash_2(N);
    for (auto i = 0; i < N; i++) {
        tau_group[i] = sp.getkey() * public_key_group[i];
        tau_group_hash[i] = calSHA256(tau_group[i]);
        tau_group_hash_2[i] = tau_group_hash[i].substr(0, range_number);
        cout << "tau group hash 2: " << tau_group_hash_2[i] << endl;
    }

    // for(auto i=0;i<N;i++){
    //     if(tau_group[i] == tau_key)
    //         cout <<"true"<<endl;
    // }
    int s = 155, r = 10;

    string H_s_3 = calSHA256(calSHA256(calSHA256(to_string(s))));
    cout << "H_s_3: " << H_s_3 << endl;
    cout << "----------- MerkleTree s --------------------" << endl;
    vector<char *> leaves_BIL(BIL.size());
    for (auto i = 0; i < leaves_BIL.size(); i++) {
        leaves_BIL[i] = new char[65];
    }
    // PRF_x(H) = H(H(bio)||s)
    for (auto i = 0; i < leaves_BIL.size(); i++) {
        strcpy(leaves_BIL[i], calSHA256(calSHA256(BIL[i]) + to_string(s)).c_str());
    }

    merkletree MTs = merkletree(leaves_BIL);
    char *root_MTs = MTs.root();
    for (auto i = 0; i < MTs.size(); i++) {
        cout << MTs.tree[i] << endl;
    }

    //计算c'
    Ciphertext c_encrypted_2;
    vector<Plaintext> c_plain_group(N);
    for (auto i = 0; i < c_plain_group.size(); i++) {
        c_plain_group[i] = Plaintext(tau_group_hash_2[i]);
        cout << "c_plain_group[0] : " << c_plain_group[i].to_string() << endl;
    }

    Ciphertext hash_c_0;
    // Ciphertext hash_c_temp;
    evaluator.sub_plain(c_encrypted, c_plain_group[0], hash_c_0);
    cout << "    + noise budget in hash_c_0 初始化: " << decryptor.invariant_noise_budget(hash_c_0) << " bits" << endl;
    Plaintext decrypted_result;
    decryptor.decrypt(hash_c_0, decrypted_result);
    cout << "hash_c_0: " << decrypted_result.to_string() << endl;
    Ciphertext hash_c;
    cout << "    + noise budget in hash_c_0: " << decryptor.invariant_noise_budget(hash_c_0) << " bits" << endl;
    // hash_c_temp = hash_c_0;
    for (auto i = 1; i < N; i++) {
        evaluator.sub_plain(c_encrypted, c_plain_group[i], hash_c);
        // evaluator.multiply(hash_c_0,hash_c,hash_c_0);
        evaluator.multiply(hash_c_0, hash_c, hash_c_0);
        // hash_c_temp = hash_c_0;
        // evaluator.relinearize_inplace(hash_c_0, relin_keys);
        // evaluator.relinearize_inplace(hash_c_temp, relin_keys);
        // cout << "    + noise budget in hash_c_0: " << decryptor.invariant_noise_budget(hash_c_0) << " bits"<<endl;
        // cout << "    + noise budget in hash_c_temp: " << decryptor.invariant_noise_budget(hash_c_temp) << "
        // bits"<<endl;
    }

    Plaintext r_plain(to_string(r));
    evaluator.multiply_plain_inplace(hash_c_0, r_plain);

    Plaintext s_plain(to_string(s));
    evaluator.add_plain(hash_c_0, s_plain, c_encrypted_2);

    decryptor.decrypt(c_encrypted_2, decrypted_result);
    cout << "c_encrypted_2: " << decrypted_result.to_string() << endl;
    cout << "    + noise budget in c_encrypted_2: " << decryptor.invariant_noise_budget(c_encrypted_2) << " bits"
         << endl;
    // evaluator.relinearize_inplace(c_encrypted_2, relin_keys);
    cout << "    + noise budget in c_encrypted_2: " << decryptor.invariant_noise_budget(c_encrypted_2) << " bits"
         << endl;

    // Ciphertext s_encrypted;
    // encryptor.encrypt(s_plain,s_encrypted);

    // Plaintext decrypted_result_s;
    // decryptor.decrypt(s_encrypted, decrypted_result_s);

    // cout <<"---------------"<<endl;
    // cout <<"---------------"<<endl;
    // cout <<"---------------"<<endl;
    // cout << decrypted_result_s.to_string() <<endl;
    timer1.stop();
    running_time["4.confirm time: "] = timer1.elapse_sec();

    timer1.clear();

    // 5. submit
    //解密c'得到s
    // int s_ = s;
    timer1.start();
    string s_ = decrypted_result.to_string();
    cout << "s_: " << s_ << endl;
    string H_s_2 = calSHA256(calSHA256(s_));

    cout << "----------- MerkleTree s' --------------------" << endl;
    // PRF_x(H) = H(H(bio)||s)
    for (auto i = 0; i < leaves_BIL.size(); i++) {
        strcpy(leaves_BIL[i], calSHA256(calSHA256(BIL[i]) + s_).c_str());
    }

    merkletree MTs_ = merkletree(leaves_BIL);
    char *root_MTs_ = MTs_.root();
    for (auto i = 0; i < MTs_.size(); i++) {
        cout << MTs_.tree[i] << endl;
    }

    if (calSHA256(H_s_2) != H_s_3 || root_MTs != root_MTs) {
        cout << "abort" << endl;
    }

    //收集u的信息产生ID
    FieldT r_number = FieldT::random_element();
    G1 gr = r_number * g;
    string H_0_xr = calSHA256(r_number * sp.pk);
    string ID = calSHA256("user name");
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
    vector<string> M_test_result = {"Alice", "man", "O", "good", "1800"};
    // vector<basic_biological> M ={{BIL[0],"Alice"},{BIL[1],"man"},{BIL[2],"O"},{BIL[3],"good"},{BIL[4],"1800"}};
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
        string strKey = calSHA256(BIL[i] + to_string(s));
        // cout <<"**key**"<<strKey<<""<<endl;
        string strOriginData = M[i].value;
        string strEncryBase64Data = EncryptAES(strKey, strOriginData);
        C_AES_base64[i] = strEncryBase64Data;
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
    for (auto i = 0; i < MT_C.size(); i++) {
        cout << MT_C.tree[i] << endl;
    }

    string H_s_1 = calSHA256(to_string(s));
    timer1.stop();
    running_time["6.result upload time: "] = timer1.elapse_sec();

    timer1.clear();

    // 7. result dispute
    //解密得到结果

    timer1.start();
    vector<string> M_dec_result(C_AES_base64.size());
    for (auto i = 0; i < BIL.size(); i++) {
        string strKey = calSHA256(BIL[i] + to_string(s));
        M_dec_result[i] = DecryptAES(strKey, C_AES_base64[i]);
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
    }
    //发现信息错误，发起dispute
    if (!compare_result) {
        cout << "************----------DISPUTE PHRASE-------**************************" << endl;
    }
    //产生错误信息节点的Merkle proof
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
        if (user.BBI[k].value == BIL[i]) {
            gamma = i;
        }
    }
    cout << gamma << endl;
    cout << k << endl;

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
    // for (map<string, double>::iterator iter = running_time.begin(); iter != running_time.end(); ++iter) {
    //     cout << iter->first << iter->second << " s " << endl;
    // }

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