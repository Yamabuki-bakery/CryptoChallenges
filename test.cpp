#include "mycrypto.h"

using namespace std;


int test(){
    char char2hex_test [] = {'0', '8', 'a' ,'b', 'D', 'F', 'q', '1'};
    uint8_t char2hex_result [] = {0, 8, 10, 11, 13, 15, 255, 1};
    for (size_t i = 0; i < 7; i++)
    {
        try
        {
            char2hex(char2hex_test[i]) == char2hex_result[i];
        }
        catch(const range_error& e)
        {
            std::cerr << e.what() << '\n';
            (255 == char2hex_result[i]);
        }
    }
   
    string str2hex_test = "0bAC";
    vector<uint8_t> str2hex_result = {0x0b, 0xac};
    vector<uint8_t> result = str2hex(str2hex_test);
    (result[0] == 0x0b && result[1] == 0xac);

    return 0;
}