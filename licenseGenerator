#include <string>
#include <iomanip>
#include <iostream>
#include <fstream>
#include "json.hpp"
#include "pb.h"

using json = nlohmann::json;
using namespace std;

// The secret key used for encryption and decryption
#define SECRET_KEY "asdgga79874TYKLH&*^&*6334D"

// Function to swap two elements in an array
void swap(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

// Function to initialize the state vector S using the key
void keySchedulingAlgorithm(int S[], string key) {
    int len = key.length(); // Get the length of the key
    for (int i = 0; i < 256; i++) { // Initialize S with values from 0 to 255
        S[i] = i;
    }
    int j = 0;
    for (int i = 0; i < 256; i++) { // Permute S using the key
        j = (j + S[i] + key[i % len]) % 256; // Calculate j using the key and S
        swap(&S[i], &S[j]); // Swap S[i] and S[j]
    }
}

// Function to generate a keystream byte from the state vector S
int pseudoRandomGenerationAlgorithm(int S[], int *i, int *j) {
    *i = (*i + 1) % 256; // Increment i by 1 modulo 256
    *j = (*j + S[*i]) % 256; // Increment j by S[i] modulo 256
    swap(&S[*i], &S[*j]); // Swap S[i] and S[j]
    int t = (S[*i] + S[*j]) % 256; // Calculate t using S[i] and S[j]
    return S[t]; // Return the keystream byte
}

// Function to encrypt or decrypt a message using RC4
string rc4(string message, string key) {
    int S[256]; // Declare the state vector S
    keySchedulingAlgorithm(S, key); // Initialize S using the key
    string result = ""; // Declare an empty string for the result
    int i = 0, j = 0; // Declare two indices i and j
    for (char c : message) { // Loop through each character of the message
        int k = pseudoRandomGenerationAlgorithm(S, &i, &j); // Generate a keystream byte k
        result += c ^ k; // XOR the character with k and append to the result
    }
    return result; // Return the encrypted or decrypted message
}

void writeHexToFile(const string& str, const string& filename) {
    ofstream file(filename);
    if (file.is_open()) {
        for (unsigned char c : str) {
            file << hex << setw(2) << setfill('0') << static_cast<int>(c);
        }
        file.close();
        cout << "write into file " << filename << " succeed!" << endl;
    } else {
        cout << "Can't open " << filename << "." << endl;
    }
}

vector<string> split(string str, char delimiter) {
    vector<string> tokens;
    size_t pos = 0;
    string token;
    while ((pos = str.find(delimiter)) != string::npos) {
        token = str.substr(0, pos);
        tokens.push_back(token);
        str.erase(0, pos + 1);
    }
    tokens.push_back(str);
    return tokens;
}

// 读取配置文件
std::map<std::string, std::string> read_ini_file(std::string filename) {
//    rotating_logger->set_level(spdlog::level::debug);
//    rotating_logger->flush_on(spdlog::level::trace);

    std::string version0 = "1.0.0";
//    rotating_logger->info("version:{} ", version0);
    printf("version:%s\n",version0.c_str());

    std::map<std::string, std::string> result;
    std::ifstream file(filename);
//    rotating_logger->info("open ini file:{}!", filename);
    if (file.is_open()) {
        std::string line;
        std::string section = "";
        while (std::getline(file, line)) {
            if (line[0] == '[' && line[line.size() - 1] == ']') {
                section = line.substr(1, line.size() - 2);
            } else if (line.find('=') != std::string::npos) {
                size_t pos = line.find('=');
                std::string key = line.substr(0, pos);
                key.erase(0,key.find_first_not_of(" "));
                key.erase(key.find_last_not_of(" ") + 1);
                std::string value = line.substr(pos + 1);
                value.erase(0,value.find_first_not_of(" "));
                value.erase(value.find_last_not_of(" ") + 1);
                result[key] = value;
            }
        }
        file.close();
        for (auto const& pair: result) {
            std::cout << pair.first << ": " << pair.second << std::endl;
//            rotating_logger->info("{}:{}!", pair.first,pair.second);
        }
        // for (auto const& [key, value] : result) {
        //     std::cout << key << " = " << value << std::endl;
        // }
    }else{
        std::cout << filename<<":can not open!"<< std::endl;
//        rotating_logger->info("{}:can not open!!", filename);
    }
    return result;
}

std::string getDayStr(int days) {
    time_t now = time(0);
    tm *ltm = localtime(&now);
    ltm->tm_mday += days;
    mktime(ltm);
    char dayStr[20];
    strftime(dayStr, sizeof(dayStr), "%Y-%m-%d", ltm);
    return dayStr;
}

int main() {
    std::map<std::string, std::string> config = read_ini_file("config.ini");
    printf("create PbApi...\n");
    PbApi* m_pb = new PbApi(config["serverIp"],config["serverPort"],config["serverProto"],config["ywlx"]);
    if(m_pb->init()) {
        printf("create PbApi succeed!\n");
    } else {
        printf("create PbApi failed!\n");
        return -1;
    }
    std::string zx_addr = m_pb->query_ZX_addr();
    std::string expiration = getDayStr(atoi(config["expire"].c_str()));

    string strKhh = config["khh"];
    strKhh.erase(std::remove(strKhh.begin(),strKhh.end(),'\r'), strKhh.end());
    vector<string> khhs = split(strKhh, ',');
    for (int i = 0; i < khhs.size(); ++i) {
        m_pb->query_SF_list(khhs[i]);
        map<string, string> algo_map;
        vector<Data> sf_list = m_pb->getAlgoList(khhs[i]);
        if (!sf_list.empty()) {
            for (int j = 0; j < sf_list.size(); ++j) {
                algo_map[sf_list[j].sf_item_4251] = sf_list[j].sf_item_110019;
            }
        }
        json j = json{{"khh",khhs[i]}, {"zx_addr",zx_addr}, {"expiration", expiration}, {"algo", algo_map}};
        string plaintext = j.dump();
        cout << "plaintext: " << plaintext << endl;
        string ciphertext = rc4(plaintext, SECRET_KEY);
        string filename = khhs[i] +"_"+expiration+".txt";
        writeHexToFile(ciphertext, filename);
    }

    return 0;
}
