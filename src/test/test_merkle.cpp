#include "../algorithm.hpp"
#include "../timer.hpp"
#include <iostream>
#include <vector>

using namespace std;

int main()
{
    int index = 0;
    while (index < 10) {
        int N = 1000 * (index + 1);
        cout << "======================= N = " << N << "=========================" << endl;
        index++;
        Timer timer;

        vector<string> nodes(N);
        for (int i = 0; i < N; i++) {
            nodes[i] = (to_string(i) + "node");
        }

        cout << "1. Build Merkle Tree: ";
        timer.start();
        merkletree MT = MTree(nodes);
        timer.stop();
        cout << timer.elapse_sec() * 1000 << endl;
        timer.clear();

        vector<char *> Mtree = MT.tree;

        auto root = MT.root();

        int index = N / 2;
        string node = to_string(index) + "node";

        cout << "2. Generate Merkle Tree Proof: ";
        timer.start();
        vector<ProofNode> proof = MTProof(MT, node);
        timer.stop();
        cout << timer.elapse_sec() * 1000 << endl;
        timer.clear();

        cout << "3. Verify Merkle Proof: ";
        timer.start();
        bool verify = MTVerif(root, node, proof);
        timer.stop();
        cout << timer.elapse_sec() * 1000 << endl;
        timer.clear();

        cout << "verify: " << verify << endl;
    }
    cout << "++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
}