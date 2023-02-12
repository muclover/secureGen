#include "../algorithm.hpp"
#include "../timer.hpp"
#include <iostream>

using namespace std;
using namespace seal;

void print(string s)
{
    cout << __LINE__ << " ******* " << s << " *******" << endl;
}

int main()
{
    int index = 0;
    int group[] = {4, 9, 14, 19, 22, 26};
    while (index < 6) {
        ppT::init_public_params();
        EncryptionParameters enc_params(scheme_type::bfv);
        uint32_t N = 32768;
        uint32_t plain_modulus = 786433;
        // uint32_t plain_modulus = 8192;

        gen_encryption_params(N, plain_modulus, enc_params);
        Encryptor_Help he_enc_tool(enc_params);
        print_parameters(*he_enc_tool.context_);

        Service_info service_info;
        print("1-Setup");
        setup(service_info);

        Server server;
        Client client;
        print("2-Register");
        user_register(service_info, server, client);

        // print("3-Service Request");
        service_request(service_info, server, client, he_enc_tool);
        // print("4-Service Confirm");
        service_info.tau_groups.push_back(client.pk);
        int group_size = group[index];
        index++;
        cout << " ====================================================== " << endl;
        cout << "---------------------- N= " << group_size << "--------------------------------------------------------------------" << endl;
        for (int i = 0; i < group_size; i++) {
            service_info.tau_groups.push_back(FieldT::random_element() * service_info.generator);
        }

        Timer timer;
        timer.start();
        service_confirm(service_info, server, he_enc_tool);
        timer.stop();
        cout << " +++++++++++++++++++++++++*************************************++++++++++++++++++++" << endl;
        cout << "Time of Algorithm 4: " << timer.elapse_sec() << endl;
        cout << " +++++++++++++++++++++++++*************************************++++++++++++++++++++" << endl;

        print("5-Sample Submit");
        sample_submit(service_info, server, he_enc_tool);
        // print("6-Result Upload");
        result_upload(service_info);
        // print("7-Result Upload");
        result_dispute(service_info, client);
        // print("8-Result Upload");
        self_prove(service_info);
    }
}