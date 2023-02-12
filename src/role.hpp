#ifndef ROLE_HPP
#define ROLE_HPP
#include "typedef.hpp"
#include <map>
#include <string>
#include <vector>

using namespace std;

// vector<string> BIL = {"1", "2", "3", "4", "5"}; // biological information labels
struct basic_biological {
    string biological;
    string value;
};

struct BIL {
    vector<basic_biological> biolabels;

    BIL(int n = 10, std::string s = "value")
    {
        biolabels.reserve(n);
        for (auto i = 0; i < n; i++) {
            biolabels.emplace_back(basic_biological{to_string(i), to_string(i) + s});
        }
    }
    BIL(const BIL &rhs)
    {
        this->biolabels = rhs.biolabels;
    }
};

class Server {
public:
    G1 pk;
    Server()
    {}
    Server(FieldT _sk, G1 _pk) :
        sk(_sk), pk(_pk), information("server")
    {}
    Server(const Server &rhs)
    {
        this->pk = rhs.pk;
        this->sk = rhs.sk;
    }
    Server &operator=(const Server &rhs)
    {
        this->pk = rhs.pk;
        this->sk = rhs.sk;
        return *this;
    }
    FieldT get_sk()
    {
        return sk;
    }
    FieldT get_sk() const
    {
        return sk;
    }

private:
    FieldT sk;
    std::string information;
};
class Client {
public:
    G1 pk;
    BIL BBI;
    std::vector<std::string> Com;
    std::vector<std::string> ds;

    Client()
    {}
    Client(FieldT sk_, G1 pk_, BIL BBI_, std::vector<std::string> com_, std::vector<std::string> ds_) :
        sk(sk_), pk(pk_), BBI(BBI_), Com(com_), ds(ds_), information("client")
    {}
    Client(const Client &rhs)
    {
        this->pk = rhs.pk;
        this->sk = rhs.sk;
        this->BBI = rhs.BBI;
        this->Com = rhs.Com;
        this->ds = rhs.ds;
    }
    ~Client() = default;
    FieldT get_sk()
    {
        return sk;
    }

    FieldT get_sk() const
    {
        return sk;
    }

private:
    FieldT sk;
    std::string information;
};

class government_agency {
public:
    G1 g;
    vector<FieldT> commitment; //对用户BBI的承诺
    // merkle_tree MTH;    //对用户BBI的承诺open值构成的Merkle树
    vector<G1> pk_sp;
    vector<G1> pk_user;
    // vector<string> sigma_sp;
    // vector<string> sigma_user;
    // u64 Timeout1;   //时间周期
    // u64 Timeout2;
    // u64 Timeout3;
};

class service_provider {
public:
    G1 pk;
    // string identity;
    service_provider(){};
    service_provider(FieldT sk, G1 g) :
        sk(sk)
    {
        pk = sk * g;
    };
    FieldT getkey()
    {
        return sk;
    }

private:
    FieldT sk;
};

class generic_user {
public:
    G1 pk;
    vector<basic_biological> BBI; // basic biological information, such as gender, blood type, ethnic ets
    // vector<FieldT> open;
    generic_user(){};
    generic_user(FieldT sk, G1 g) :
        sk(sk)
    {
        pk = sk * g;
        BBI.push_back(basic_biological{"1", "32636lice"});
        BBI.push_back(basic_biological{"2", "man"});
        BBI.push_back(basic_biological{"3", "53425wggwgw "});
        BBI.push_back(basic_biological{"4", "sfjls"});
        BBI.push_back(basic_biological{"5", "sgjsaolg"});
    };
    FieldT getkey()
    {
        return sk;
    }

private:
    FieldT sk;
};

#endif // ROLE_HPP
