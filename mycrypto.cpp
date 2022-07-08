#include "mycrypto.h"

// using namespace std;

// 只支持 AES 128 EBC

std::vector<uint8_t> AES::encrypt_block(std::vector<uint8_t> state)
{
    this->apply_round_key(state, this->key);
    for (size_t i = 0; i < this->round - 1; i++)
    {
        this->sub_bytes(state, sbox);
        this->shift_rows(state, true);
        this->mix_columns(state, true);
        this->apply_round_key(state, this->round_keys[i]);
    }
    this->sub_bytes(state, sbox);
    this->shift_rows(state, true);
    this->apply_round_key(state, this->round_keys[round - 1]);
}

void AES::mix_columns(std::vector<uint8_t> &state, bool encrypt)
{
    for (size_t i = 0; i < 4; i++)
    {
        uint8_t *col_start = &state[i * 4];
        uint8_t origin_byte0 = col_start[0];
        uint8_t origin_byte1 = col_start[1];
        uint8_t origin_byte2 = col_start[2];
        uint8_t origin_byte3 = col_start[3];
        if (encrypt)
        {
            col_start[0] = gMulBy2[origin_byte0] ^ gMulBy3[origin_byte1] ^ origin_byte2 ^ origin_byte3;
            col_start[1] = origin_byte0 ^ gMulBy2[origin_byte1] ^ gMulBy3[origin_byte2] ^ origin_byte3;
            col_start[2] = origin_byte0 ^ origin_byte1 ^ gMulBy2[origin_byte2] ^ gMulBy3[origin_byte3];
            col_start[3] = gMulBy3[origin_byte0] ^ origin_byte1 ^ origin_byte2 ^ gMulBy2[origin_byte3];
        }
        else
        {
            col_start[0] = gMulBy14[origin_byte0] ^ gMulBy11[origin_byte1] ^ gMulBy13[origin_byte2] ^ gMulBy9 [origin_byte3];
            col_start[1] = gMulBy9 [origin_byte0] ^ gMulBy14[origin_byte1] ^ gMulBy11[origin_byte2] ^ gMulBy13[origin_byte3];
            col_start[2] = gMulBy13[origin_byte0] ^ gMulBy9 [origin_byte1] ^ gMulBy14[origin_byte2] ^ gMulBy11[origin_byte3];
            col_start[3] = gMulBy11[origin_byte0] ^ gMulBy13[origin_byte1] ^ gMulBy9 [origin_byte2] ^ gMulBy14[origin_byte3];
        };
    }
}

void AES::shift_rows(std::vector<uint8_t> &state, bool encrypt)
{
    if (encrypt)
    {
        uint8_t temp2 = state[13];
        state[13] = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = temp2;
        uint8_t temp3 = state[6];
        state[6] = state[14];
        state[14] = temp3;
        temp3 = state[2];
        state[2] = state[10];
        state[10] = temp3;
        uint8_t temp4 = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = temp4;
    }
    else
    {
        uint8_t temp2 = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = temp2;
        uint8_t temp3 = state[6];
        state[6] = state[14];
        state[14] = temp3;
        temp3 = state[2];
        state[2] = state[10];
        state[10] = temp3;
        uint8_t temp4 = state[15];
        state[15] = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = temp4;
    }
}

void AES::sub_bytes(std::vector<uint8_t> &state, const uint8_t sbox[])
{
    for (size_t i = 0; i < state.size(); i++)
    {
        state[i] = sbox[state[i]];
    }
}

void AES::apply_round_key(std::vector<uint8_t> &state, std::vector<uint8_t> key)
{
    for (size_t i = 0; i < 16; i++)
    {
        state[i] ^= key[i];
    }
}

void AES::gen_round_keys()
{
    // https://braincoke.fr/blog/2020/08/the-aes-key-schedule-explained/#rotword
    std::vector<uint8_t> prev = this->key;
    for (size_t i = 0; i < this->round; i++)
    {
        uint32_t *prev_rkey = (uint32_t *)&prev[0];
        uint32_t *new_rkey = (uint32_t *)&(this->round_keys[i][0]);

        // Rot Word
        uint32_t m_last = prev_rkey[3];
        m_last = ((m_last & 0x000000ff) << 24) | (m_last >> 8);
        // Sub Word
        uint8_t *b1 = (uint8_t *)&m_last;
        for (size_t i = 0; i < 4; i++)
        {
            b1[i] = sbox[b1[i]];
        }
        // Rcon
        m_last ^= rcon[i];

        new_rkey[0] = prev_rkey[0] ^ m_last;
        for (size_t i = 1; i < 4; i++)
        {
            new_rkey[i] = prev_rkey[i] ^ new_rkey[i - 1];
        }
        prev = this->round_keys[i];
    }
}

AES::AES(std::vector<uint8_t> key)
{
    if (key.size() != 16)
    {
        printf("[AES::AES] 密鑰長度 %i 過於惡俗", key.size());
        throw std::length_error("[AES::AES] 過於惡俗！");
    }

    this->key = key;
    this->round = 10;
    this->round_keys = std::vector<std::vector<uint8_t>>(round, std::vector<uint8_t>(16, 0));
    this->gen_round_keys();
}

AES::~AES()
{
}

/*
 * @brief Calc Hamming destance of 2 strings.
 * @param seq1 string one
 * @param seq2 string two
 * @return result
 */
int hamming_distance(std::string seq1, std::string seq2)
{
    return hamming_distance(
        std::vector<uint8_t>(seq1.begin(), seq1.end()),
        std::vector<uint8_t>(seq2.begin(), seq2.end()));
}

/*
 * @brief Calc Hamming destance of 2 byte arrays.
 * @param seq1 byte array one
 * @param seq2 byte array two
 * @return result
 */
int hamming_distance(std::vector<uint8_t> seq1, std::vector<uint8_t> seq2)
{
    std::vector<uint8_t> xored = xor2buff(seq1, seq2);
    int result = 0;
    for (size_t i = 0; i < xored.size(); i++)
    {
        uint8_t target = xored[i];
        int count = 0;
        while (target)
        {
            target &= (target - 1);
            count++;
        }
        result += count;
    }
    return result;
}

/*
 * @brief Generate a repeating key with given length.
 * @param sequence a string use as key.
 * @param length Given length
 * @return result
 */
std::vector<uint8_t> gen_repeating_xor_key(std::string sequence, int length)
{
    return gen_repeating_xor_key(
        std::vector<uint8_t>(sequence.begin(), sequence.end()),
        length);
}

/*
 * @brief Generate a repeating key with given length.
 * @param sequence a raw byte array vector use as key.
 * @param length Given length
 * @return result
 */
std::vector<uint8_t> gen_repeating_xor_key(std::vector<uint8_t> sequence, int length)
{
    std::vector<uint8_t> result(length, 0);
    int key_len = sequence.size();
    int groups = length / key_len;
    int lasted = length - groups * key_len;

    for (size_t i = 0; i < key_len; i++)
    {
        for (size_t j = 0; j < groups; j++)
        {
            result[j * key_len + i] = sequence[i];
        }
    }
    // deal with last
    for (size_t i = 0; i < lasted; i++)
    {
        result[groups * key_len + i] = sequence[i];
    }
    return result;
}

/*
 * @brief decrypt a single XORed byte array using English readibility score.
 * @param byte_array a raw byte array vector to decrypt.
 * @param __return_key A pointer to int to receive the best key.
 * @param __return_decrypted_result A pointer to return the decrypt result.
 * @return An int of the best decrypt score tried.
 */
int decrypt_with_score(
    std::vector<uint8_t> byte_array,
    uint8_t *__return_key,
    std::vector<uint8_t> *__return_decrypted_result)
{
    int best_score = -999999999;
    uint8_t key;
    std::vector<uint8_t> *result = new std::vector<uint8_t>;
    for (size_t i = 0; i < 256; i++)
    {
        std::vector<uint8_t> *temp = new std::vector<uint8_t>;
        for (size_t j = 0; j < byte_array.size(); j++)
        {
            temp->push_back(byte_array[j] ^ i);
        }
        int new_score = score_in_eng(*temp);
        if (new_score > best_score)
        {
            delete result;
            best_score = new_score;
            key = i;
            result = temp;
        }
        else
        {
            delete temp;
        }
    }

    // std::cout //<< "The best key is: " << key << std::endl
    // << "The best score is: " << best_score << std::endl
    // << "The best decrypt is: " << std::string(result->begin(), result->end()) << std::endl;
    // delete result;
    *__return_key = key;
    *__return_decrypted_result = *result;
    return best_score;
}

/*
 * @brief score a byte sequence the possibility of an English sentence.
 * @param byte_array a raw byte array vector.
 * @return An int of the score, higher is better.
 */
int score_in_eng(std::vector<uint8_t> byte_array)
{
    int score = 0;
    int space_count = 0;
    int letter_count = 0;
    int number_count = 0;
    int ascii_other = 0;
    int extend_ascii = 0;

    for (size_t i = 0; i < byte_array.size(); i++)
    {
        char byte = byte_array[i];
        if (byte == ' ')
        {
            space_count++;
        }
        else if ((byte > 'a' && byte < 'z') || (byte > 'A' && byte < 'Z'))
        {
            letter_count++;
        }
        else if (byte > '0' && byte < '9')
        {
            number_count++;
        }
        else if (byte >= 0 && byte < 128)
        {
            ascii_other++;
        }
        else
            extend_ascii++;
    }
    if (space_count)
        space_count--;

    score = score + 5 * space_count + letter_count - number_count - 3 * ascii_other - 5 * extend_ascii;
    return score;
}

/*
 * @brief XOR a vector of bytes against another.
 * @param buff1 a raw byte array vector.
 * @param buff2 a raw byte array vector.
 * @return The result vector.
 */
std::vector<uint8_t> xor2buff(std::vector<uint8_t> buff1, std::vector<uint8_t> buff2)
{
    if (buff1.size() != buff2.size())
    {
        printf("[xor2buff] 輸入的長度過於惡俗！One: %i, Two %i\n", buff1.size(), buff2.size());
        throw std::length_error("[xor2buff] 過於惡俗！");
    }
    for (size_t i = 0; i < buff1.size(); i++)
    {
        buff1[i] = buff1[i] ^ buff2[i];
    }
    return buff1;
}

std::string b64encode(std::vector<uint8_t> data)
{
    std::vector<char> result;
    const int last = data.size() % 3;
    const int groups = data.size() / 3;
    for (size_t i = 0; i < groups; i++)
    {
        uint8_t t1 = data[3 * i];
        uint8_t t2 = data[3 * i + 1];
        uint8_t t3 = data[3 * i + 2];
        uint32_t bits = (t1 << 16) + (t2 << 8) + t3;
        uint8_t sex1 = (bits & 0b111111000000000000000000) >> 18;
        uint8_t sex2 = (bits & 0b000000111111000000000000) >> 12;
        uint8_t sex3 = (bits & 0b000000000000111111000000) >> 6;
        uint8_t sex4 = (bits & 0b000000000000000000111111);

        result.push_back(b64encode_table[sex1]);
        result.push_back(b64encode_table[sex2]);
        result.push_back(b64encode_table[sex3]);
        result.push_back(b64encode_table[sex4]);
    }

    if (last == 2)
    {
        uint8_t t1 = data[3 * groups];
        uint8_t t2 = data[3 * groups + 1];
        uint32_t bits = (t1 << 16) + (t2 << 8);
        uint8_t sex1 = (bits & 0b111111000000000000000000) >> 18;
        uint8_t sex2 = (bits & 0b000000111111000000000000) >> 12;
        uint8_t sex3 = (bits & 0b000000000000111111000000) >> 6;

        result.push_back(b64encode_table[sex1]);
        result.push_back(b64encode_table[sex2]);
        result.push_back(b64encode_table[sex3]);
        result.push_back('=');
    }
    else if (last == 1)
    {
        uint8_t t1 = data[3 * groups];
        uint32_t bits = (t1 << 16);
        uint8_t sex1 = (bits & 0b111111000000000000000000) >> 18;
        uint8_t sex2 = (bits & 0b000000111111000000000000) >> 12;

        result.push_back(b64encode_table[sex1]);
        result.push_back(b64encode_table[sex2]);
        result.push_back('=');
        result.push_back('=');
    }

    return std::string(result.begin(), result.end());
}

static inline bool is_base64(uint8_t c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::vector<uint8_t> b64decode(std::string encoded_string)
{
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int index = 0;
    uint8_t char_array_4[4], char_array_3[3];
    std::vector<uint8_t> ret;

    while (1)
    {
        if (in_len-- && (encoded_string[index] != '=') && is_base64(encoded_string[index]))
        {
            // do nothing
        }
        else if (encoded_string[index] == '\n' || encoded_string[index] == '\r')
        {
            index++;
            continue;
        }
        else
            break;

        char_array_4[i++] = encoded_string[index];
        index++;
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++)
            ret.push_back(char_array_3[j]);
    }
    return ret;
}

std::vector<uint8_t> str2hex(std::string origin)
{
    int length = origin.length();
    if (length % 2)
    {
        printf("[str2hex] origin length %i is not even.\n", length);
        throw std::length_error("[str2hex] 過於惡俗！");
    }

    std::vector<uint8_t> result;
    int count = length / 2;
    for (size_t i = 0; i < count; i++)
    {
        char char_1 = origin[i * 2];
        char char_2 = origin[i * 2 + 1];

        uint8_t one_hex = char2hex(char_1) * 16 + char2hex(char_2);
        result.push_back(one_hex);
    }
    return result;
}

uint8_t char2hex(char origin)
{
    if (origin <= 57 && origin >= 48) // number
    {
        return origin - 48;
    }
    else if (origin <= 70 && origin >= 65) // capital letter
    {
        return origin - 55;
    }
    else if (origin <= 102 && origin >= 97) // lowercase
    {
        return origin - 87;
    }
    else
    {
        printf("[char2hex] 過於惡俗！ %c\n", origin);
        throw std::range_error("[char2hex] 過於惡俗！");
    }
}

void print_hex(std::vector<uint8_t> target)
{
    char table[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    for (size_t i = 0; i < target.size(); i++)
    {
        char high = target[i] / 16;
        char low = target[i] % 16;
        std::cout << table[high] << table[low];
    }
    std::cout << std::endl;
}