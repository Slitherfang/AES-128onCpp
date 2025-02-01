#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <cstring>
#include <atomic>
#include <thread>
#include <mutex>
#include <iomanip>
#include <filesystem>

//懒得改位置了，直接提供函数原型
void AES_DecryptBlock(uint8_t* block, const uint8_t* roundKeys);
void AES_EncryptBlock(uint8_t* block, const uint8_t* roundKeys);

//互斥锁，防止多线程同时访问共享资源导致错误
std::mutex progress_mutex;
std::atomic<uintmax_t> processed_blocks(0);

void ShowProgress(uintmax_t total_blocks) {
    while (processed_blocks < total_blocks) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        float progress = static_cast<float>(processed_blocks) / total_blocks;
        int bar_width = 50;
        
        std::lock_guard<std::mutex> lock(progress_mutex);
        std::cout << "[";
        int pos = bar_width * progress;
        for (int i = 0; i < bar_width; ++i) {
            if (i < pos) std::cout << "=";
            else if (i == pos) std::cout << ">";
            else std::cout << " ";
        }
        std::cout << "] " << std::setw(3) << int(progress * 100.0) << " %\r";
        std::cout.flush();
    }
}

struct BlockData {
    uint8_t data[16];
    uintmax_t index;
};

void ProcessBlocks(const uint8_t* roundKeys, 
                  bool encrypt,
                  const uint8_t* file_data,
                  uintmax_t file_size,
                  uint8_t* output_data,
                  uintmax_t start_block,
                  uintmax_t end_block) {
    for (uintmax_t i = start_block; i < end_block; ++i) {
        BlockData block;
        uintmax_t offset = i * 16;
        uintmax_t data_size = std::min<uintmax_t>(16, file_size - offset);
        
        // 复制数据块
        std::memset(block.data, 0, 16);
        std::memcpy(block.data, file_data + offset, data_size);
        block.index = i;

        // 处理填充（仅加密的最后一个块）
        if (encrypt && (i == end_block - 1) && (data_size < 16)) {
            uint8_t padding = 16 - data_size;
            std::memset(block.data + data_size, padding, padding);
        }

        // 执行加密/解密
        if (encrypt) {
            AES_EncryptBlock(block.data, roundKeys);
        } else {
            AES_DecryptBlock(block.data, roundKeys);
            
            // 处理解密填充（最后一个块）
            if (i == end_block - 1) {
                uint8_t padding = block.data[15];
                if (padding > 0 && padding <= 16) {
                    std::memset(block.data + (16 - padding), 0, padding);
                }
            }
        }

        // 写入输出缓冲区
        std::memcpy(output_data + offset, block.data, 16);
        ++processed_blocks;
    }
}

// --------------------- AES 核心参数 ---------------------
#define AES_BLOCK_SIZE 16
#define AES_ROUNDS 10
#define AES_KEY_SIZE 16

// --------------------- S盒 & 逆S盒 ---------------------
const uint8_t sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// --------------------- 密钥扩展 ---------------------
void KeyExpansion(const uint8_t* key, uint8_t* roundKeys) {
    uint8_t temp[4];
    
    // 初始密钥拷贝
    for (int i = 0; i < AES_KEY_SIZE; ++i) {
        roundKeys[i] = key[i];
    }

    // 扩展剩余轮密钥
    for (int i = AES_KEY_SIZE; i < AES_BLOCK_SIZE * (AES_ROUNDS + 1); i += 4) {
        temp[0] = roundKeys[i - 4];
        temp[1] = roundKeys[i - 3];
        temp[2] = roundKeys[i - 2];
        temp[3] = roundKeys[i - 1];

        if (i % AES_KEY_SIZE == 0) {
            // RotWord
            uint8_t tmp = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = tmp;

            // SubWord
            for (int j = 0; j < 4; ++j) {
                temp[j] = sbox[temp[j]];
            }

            // Rcon
            temp[0] ^= (0x01 << ((i / AES_KEY_SIZE) - 1));
        }

        for (int j = 0; j < 4; ++j) {
            roundKeys[i + j] = roundKeys[i - AES_KEY_SIZE + j] ^ temp[j];
        }
    }
}

// --------------------- 加密操作 ---------------------
void SubBytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) {
        state[i] = sbox[state[i]];
    }
}

void ShiftRows(uint8_t state[16]) {
    uint8_t temp[16];
    temp[0] = state[0];
    temp[1] = state[5];
    temp[2] = state[10];
    temp[3] = state[15];
    temp[4] = state[4];
    temp[5] = state[9];
    temp[6] = state[14];
    temp[7] = state[3];
    temp[8] = state[8];
    temp[9] = state[13];
    temp[10] = state[2];
    temp[11] = state[7];
    temp[12] = state[12];
    temp[13] = state[1];
    temp[14] = state[6];
    temp[15] = state[11];
    std::copy(temp, temp+16, state);
}

uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        bool hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

void MixColumns(uint8_t state[16]) {
    for (int i = 0; i < 4; ++i) {
        uint8_t s0 = state[4*i];
        uint8_t s1 = state[4*i+1];
        uint8_t s2 = state[4*i+2];
        uint8_t s3 = state[4*i+3];

        state[4*i]   = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3;
        state[4*i+1] = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3;
        state[4*i+2] = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3);
        state[4*i+3] = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3);
    }
}

void AddRoundKey(uint8_t state[16], const uint8_t* roundKey) {
    for (int i = 0; i < 16; ++i) {
        state[i] ^= roundKey[i];
    }
}

void AES_EncryptBlock(uint8_t* block, const uint8_t* roundKeys) {
    AddRoundKey(block, roundKeys);

    for (int round = 1; round < AES_ROUNDS; ++round) {
        SubBytes(block);
        ShiftRows(block);
        MixColumns(block);
        AddRoundKey(block, roundKeys + round*16);
    }

    // 最后一轮
    SubBytes(block);
    ShiftRows(block);
    AddRoundKey(block, roundKeys + AES_ROUNDS*16);
}

// --------------------- 解密操作 ---------------------
void InvSubBytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) {
        state[i] = inv_sbox[state[i]];
    }
}

void InvShiftRows(uint8_t state[16]) {
    uint8_t temp[16];
    temp[0] = state[0];
    temp[1] = state[13];
    temp[2] = state[10];
    temp[3] = state[7];
    temp[4] = state[4];
    temp[5] = state[1];
    temp[6] = state[14];
    temp[7] = state[11];
    temp[8] = state[8];
    temp[9] = state[5];
    temp[10] = state[2];
    temp[11] = state[15];
    temp[12] = state[12];
    temp[13] = state[9];
    temp[14] = state[6];
    temp[15] = state[3];
    std::copy(temp, temp+16, state);
}

void InvMixColumns(uint8_t state[16]) {
    for (int i = 0; i < 4; ++i) {
        uint8_t s0 = state[4*i];
        uint8_t s1 = state[4*i+1];
        uint8_t s2 = state[4*i+2];
        uint8_t s3 = state[4*i+3];

        state[4*i]   = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3);
        state[4*i+1] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3);
        state[4*i+2] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3);
        state[4*i+3] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3);
    }
}

void AES_DecryptBlock(uint8_t* block, const uint8_t* roundKeys) {
    AddRoundKey(block, roundKeys + AES_ROUNDS*16);

    for (int round = AES_ROUNDS-1; round >= 1; --round) {
        InvShiftRows(block);
        InvSubBytes(block);
        AddRoundKey(block, roundKeys + round*16);
        InvMixColumns(block);
    }

    // 最后一轮
    InvShiftRows(block);
    InvSubBytes(block);
    AddRoundKey(block, roundKeys);
}

// --------------------- 文件操作 ---------------------
void ProcessFile(const std::string& inputFile, 
                const std::string& outputFile,
                const uint8_t* key,
                bool encrypt) {
    // 密钥扩展
    uint8_t roundKeys[(AES_ROUNDS + 1) * 16];
    KeyExpansion(key, roundKeys);

    // 获取文件大小
    uintmax_t file_size = std::filesystem::file_size(inputFile);
    std::cout << "File size:" << file_size << "bytes" << std::endl;
    uintmax_t total_blocks = (file_size + 15) / 16; // 计算总块数

    // 内存映射文件，以进行文件快速处理
    std::cout << "Mapping file to memory..." << std::endl;
    std::ifstream in(inputFile, std::ios::binary);
    std::vector<uint8_t> input_data(file_size);
    in.read(reinterpret_cast<char*>(input_data.data()), file_size);
    in.close();

    // 准备输出缓冲区
    uintmax_t output_size = encrypt ? total_blocks * 16 : file_size;
    std::vector<uint8_t> output_data(output_size);

    // 启动进度显示线程
    processed_blocks = 0;
    std::thread progress_thread(ShowProgress, total_blocks);

    // 设置并发线程数（根据CPU核心数调整）
    unsigned num_threads = std::thread::hardware_concurrency();
    num_threads = num_threads ? num_threads : 4;
    std::vector<std::thread> workers;
    std::cout << "Number of threads:" << num_threads << std::endl;

    // 分配任务给线程
    uintmax_t blocks_per_thread = total_blocks / num_threads;
    for (unsigned i = 0; i < num_threads; ++i) {
        uintmax_t start = i * blocks_per_thread;
        uintmax_t end = (i == num_threads - 1) ? total_blocks : start + blocks_per_thread;
        
        workers.emplace_back(
            ProcessBlocks,
            roundKeys,
            encrypt,
            input_data.data(),
            file_size,
            output_data.data(),
            start,
            end
        );
    }

    // 等待所有线程完成
    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }

    // 完成进度条并换行
    {
        std::lock_guard<std::mutex> lock(progress_mutex);
        ShowProgress(total_blocks);
    }
    progress_thread.join();

    // 写入输出文件（解密时可能需要截断）
    std::cout << std::endl;
    std::cout << "Writing file..." << std::endl;
    std::ofstream out(outputFile, std::ios::binary);
    if (encrypt) {
        out.write(reinterpret_cast<char*>(output_data.data()), output_size);
    } else {
        // 处理解密后的填充
        uint8_t last_block[16];
        std::memcpy(last_block, output_data.data() + (total_blocks-1)*16, 16);
        uint8_t padding = last_block[15];
        
        if (padding > 0 && padding <= 16) {
            output_size -= padding;
        }
        out.write(reinterpret_cast<char*>(output_data.data()), output_size);
    }
}

int main(int argc, char* argv[]) {
    try {
        if (argc != 5) {
            std::cerr << "Usege: " << argv[0] 
                      << " <encrypt/decrypt> <inputfile> <outputfile> <16-byte key in HEX>\n";
            return 1;
        }

        // 解析密钥
        if (strlen(argv[4]) != 32) {
            throw std::runtime_error("The key must be a 32-character hexadecimal string.");
        }

        uint8_t key[16];
        for (int i = 0; i < 16; ++i) {
            key[i] = static_cast<uint8_t>(strtoul(argv[4] + 2*i, nullptr, 16));
        }

        bool encrypt = (strcmp(argv[1], "encrypt") == 0);
        ProcessFile(argv[2], argv[3], key, encrypt);

        std::cout << "The operation completed successfully\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}