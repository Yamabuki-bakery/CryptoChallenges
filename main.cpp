#include "mycrypto.h"
#include <fstream>
#include <iomanip>

// using namespace me;
using namespace std;

int main(int argc, char **argv){
    AES mAES = AES(str2hex("01020304050607080910111213141516"));
    cout << "The key is:" <<endl;
    print_hex(mAES.key);
    // for (size_t i = 0; i < mAES.round; i++)
    // {
    //     cout << "Round " << i + 1 << " Key:" <<endl;
    //     print_hex(mAES.round_keys[i]);
    // }
    mAES.encrypt_block(str2hex("00112233445566778899aabbccddeeff"));
}

int main1_6(int argc, char **argv)
{
    std::streampos fileSize;
    std::ifstream file("challenge6.txt", std::ios::binary);

    // get its size:
    file.seekg(0, std::ios::end);
    fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // read the data:
    std::vector<uint8_t> fileData(fileSize);
    file.read((char *)&fileData[0], fileSize);

    string b64(fileData.begin(), fileData.end());
    vector<uint8_t> cipher_data = b64decode(b64);

    // #define FIXED_FLOAT(x) std::fixed << std::setprecision(2) << (x)
    // printf("Ksize\tHdist\n");
    // for (size_t KEYSIZE = 2; KEYSIZE < 41; KEYSIZE++)
    // {
    //     vector<uint8_t> first(cipher_data.begin(), cipher_data.begin() + KEYSIZE);
    //     vector<uint8_t> second(cipher_data.begin() + KEYSIZE, cipher_data.begin() + 2 * KEYSIZE);
    //     vector<uint8_t> third(cipher_data.begin() + 2 * KEYSIZE, cipher_data.begin() + 3 * KEYSIZE);
    //     vector<uint8_t> forth(cipher_data.begin() + 3 * KEYSIZE, cipher_data.begin() + 4 * KEYSIZE);

    //     int d1 = hamming_distance(first, second);
    //     int d2 = hamming_distance(first, third);
    //     int d3 = hamming_distance(first, forth);
    //     float d = (((float)d1 + (float)d2 + (float)d3) / 3.0) / (float)KEYSIZE;

    //     cout << KEYSIZE << ",\t" << FIXED_FLOAT(d) << endl;
    // }

    int possible_keysize[] = {29, 5, 7};
    for (size_t i = 0; i < 5; i++)
    {
        int keysize = possible_keysize[i];
        int blocks = cipher_data.size() / keysize;
        printf("密文的長度是 %i，keysize 是 %i，分開 %i 個 block.\n", cipher_data.size(), keysize, blocks);
        vector<vector<uint8_t>> cake(blocks, vector<uint8_t>(keysize, 0));
        for (size_t i = 0; i < blocks; i++)
        {
            for (size_t j = 0; j < keysize; j++)
            {
                cake[i][j] = cipher_data[i * keysize + j];
            }
        }
        printf("調查了 %i 個 block\n", blocks);

        vector<vector<uint8_t>> transform(keysize, vector<uint8_t>(blocks, 0));
        for (size_t i = 0; i < keysize; i++)
        {
            for (size_t j = 0; j < blocks; j++)
            {
                transform[i][j] = cake[j][i];
            }
        }
        printf("完成了 轉置，開始破解 single byte XOR\n", blocks);
        std::vector<uint8_t> *result = new std::vector<uint8_t>;
        std::vector<uint8_t> key(keysize, 0);
        for (size_t i = 0; i < keysize; i++)
        {
            printf("正在破解密鑰的第 %i 位，共 %i 位: ", i + 1, keysize);
            uint8_t keyByte = 0;
            int score = decrypt_with_score(transform[i], &key[i], result);
            cout << "Score: "<< score << " key: " << key[i] << endl;
        }
        printf("我宣佈密鑰是: \n");
        print_hex(key);
        vector<uint8_t> full_key = gen_repeating_xor_key(key, cipher_data.size());
        vector<uint8_t> plain = xor2buff(full_key, cipher_data);
        printf("我宣佈解密結果是: \n");
        cout << string(plain.begin(), plain.end()) << endl;
        //break;
    }
    
    return 0;
}

int main1_5(int argc, char **argv)
{
    string plain = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    vector<uint8_t> key = gen_repeating_xor_key("ICE", plain.length());
    vector<uint8_t> cipher = xor2buff(std::vector<uint8_t>(plain.begin(), plain.end()), key);
    print_hex(cipher);

    return 0;
}

int main1_4(int argc, char **argv) // line 171 Now that the party is jumping
{
    fstream chal4;
    chal4.open("challenge4.txt");
    string one_line;

    int line_count = 0;
    uint8_t key = 0;
    std::vector<uint8_t> *result = new std::vector<uint8_t>;

    cout << "Line\tScore\tKey\tResult" << endl;

    while (getline(chal4, one_line))
    {
        line_count++;
        vector<uint8_t> byte_array = str2hex(one_line);
        int score = decrypt_with_score(byte_array, &key, result);
        if (score <= 0)
        {
            continue;
        }

        cout << line_count << "\t" << score << "\t" << key << "\t" << std::string(result->begin(), result->end())
             << endl;
    }
    delete result;
    return 0;
}

int main1_3(int argc, char **argv)
{ // Cooking MC's like a pound of bacon
    string chiper = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    vector<uint8_t> byte_array = str2hex(chiper);

    uint8_t key = 0;
    std::vector<uint8_t> *result = new std::vector<uint8_t>;
    int score = decrypt_with_score(byte_array, &key, result);
    cout
        << "Score\tKey\tResult" << endl
        << score << "\t" << key << "\t" << std::string(result->begin(), result->end())
        << endl;

    delete result;
    return 0;
}

int main1_2(int argc, char **argv)
{
    printf("[main] Input 1 hex string:\n");
    string target1 = string();
    getline(cin, target1);
    printf("[main] Input 2 hex string:\n");
    string target2 = string();
    getline(cin, target2);

    vector<uint8_t> byte_array1 = str2hex(target1);
    vector<uint8_t> byte_array2 = str2hex(target2);

    print_hex(xor2buff(byte_array1, byte_array2));
    return 0;
}

int main1_1(int argc, char **argv)
{
    printf("[main] Input a hex string:\n");
    string target = string();
    getline(cin, target);

    vector<uint8_t> byte_array = str2hex(target);
    // print_hex(byte_array);
    string b64result = b64encode(byte_array);
    cout << "[main] base 64 encode result:\n"
         << b64result << endl;

    return 0;
}
