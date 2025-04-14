#include <stdio.h>  
#include <stdlib.h> 
#include <string.h>

// Định nghĩa các mã lỗi
enum errorCode
{
    SUCCESS = 0,                    // Thành công
    ERROR_AES_UNKNOWN_KEYSIZE,      // Lỗi: Kích thước khóa không xác định
    ERROR_MEMORY_ALLOCATION_FAILED, // Lỗi: Cấp phát bộ nhớ thất bại
};
 
// Bảng S-Box cho AES (dùng để thay thế byte trong quá trình mã hóa)
unsigned char sbox[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}; // F
 
// Bảng S-Box ngược cho AES (dùng để thay thế byte trong quá trình giải mã)
unsigned char rsbox[256] =
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

// Lấy giá trị từ S-Box
unsigned char getSBoxValue(unsigned char num);
// Lấy giá trị từ S-Box ngược
unsigned char getSBoxInvert(unsigned char num);
 
// Xoay trái một word 8 bit
void rotate(unsigned char *word);
 
// Bảng Rcon cho việc mở rộng khóa
unsigned char Rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
    0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
    0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
    0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
    0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
    0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
    0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb};
 
// Lấy giá trị từ Rcon
unsigned char getRconValue(unsigned char num);
 
// Hàm core cho việc lập lịch khóa
void core(unsigned char *word, int iteration);
 
// Định nghĩa kích thước khóa (16, 24 hoặc 32 byte)
enum keySize
{
    SIZE_16 = 16, // Khóa 128-bit
    SIZE_24 = 24, // Khóa 192-bit
    SIZE_32 = 32  // Khóa 256-bit
};
 
// Mở rộng khóa cho AES
void expandKey(unsigned char *expandedKey, unsigned char *key, enum keySize, size_t expandedKeySize);
 
// Thay thế byte bằng S-Box
void subBytes(unsigned char *state);
// Dịch chuyển các hàng
void shiftRows(unsigned char *state);
// Dịch chuyển một hàng cụ thể
void shiftRow(unsigned char *state, unsigned char nbr);
// Cộng khóa vòng
void addRoundKey(unsigned char *state, unsigned char *roundKey);
// Nhân trong trường Galois (dùng cho mixColumns)
unsigned char galois_multiplication(unsigned char a, unsigned char b);
// Trộn các cột
void mixColumns(unsigned char *state);
// Trộn một cột cụ thể
void mixColumn(unsigned char *column);
// Thực hiện một vòng mã hóa AES
void aes_round(unsigned char *state, unsigned char *roundKey);
// Tạo khóa cho mỗi vòng
void createRoundKey(unsigned char *expandedKey, unsigned char *roundKey);
// Thân chính của thuật toán mã hóa AES
void aes_main(unsigned char *state, unsigned char *expandedKey, int nbrRounds);
// Hàm mã hóa AES
char aes_encrypt(unsigned char *input, unsigned char *output, unsigned char *key, enum keySize size);

// Thay thế byte bằng S-Box ngược (giải mã)
void invSubBytes(unsigned char *state);
// Dịch chuyển ngược các hàng (giải mã)
void invShiftRows(unsigned char *state);
// Dịch chuyển ngược một hàng cụ thể (giải mã)
void invShiftRow(unsigned char *state, unsigned char nbr);
// Trộn ngược các cột (giải mã)
void invMixColumns(unsigned char *state);
// Trộn ngược một cột cụ thể (giải mã)
void invMixColumn(unsigned char *column);
// Thực hiện một vòng giải mã AES
void aes_invRound(unsigned char *state, unsigned char *roundKey);
// Thân chính của thuật toán giải mã AES
void aes_invMain(unsigned char *state, unsigned char *expandedKey, int nbrRounds);
// Hàm giải mã AES
char aes_decrypt(unsigned char *input, unsigned char *output, unsigned char *key, enum keySize size);

// Hàm chính
int main() {
    unsigned char plaintext[16], key[16];
    char filename[] = "input.txt";

    // Đọc dữ liệu từ tệp
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Loi: Khong mo duoc file %s\n", filename);
        exit(1);
    }

    char line[256];
    // Đọc dòng đầu tiên
    if (!fgets(line, sizeof(line), file)) {
        fprintf(stderr, "Loi: Khong doc duoc dong dau tien cua file %s\n", filename);
        fclose(file);
        exit(1);
    }
    line[strcspn(line, "\r\n")] = 0;
    if (strncmp(line, "\xEF\xBB\xBF", 3) == 0) {
        fprintf(stderr, "Loi: File %s chua BOM UTF-8. Hay luu dang ASCII\n", filename);
        fclose(file);
        exit(1);
    }
    if (strncmp(line, "plaintext: \"", 12) != 0) {
        fprintf(stderr, "Loi: Dong dau tien phai bat dau bang 'plaintext: \"'. Noi dung doc duoc: '%s'\n", line);
        fclose(file);
        exit(1);
    }
    if (strlen(line + 12) < 17 || line[12 + 16] != '"') {
        fprintf(stderr, "Loi: Plaintext phai co dung 16 ky tu trong dau ngoac kep, doc duoc: '%s'\n", line + 12);
        fclose(file);
        exit(1);
    }
    strncpy((char *)plaintext, line + 12, 16);

    // Đọc dòng thứ hai
    if (!fgets(line, sizeof(line), file)) {
        fprintf(stderr, "Loi: Khong doc duoc dong thu hai cua file %s\n", filename);
        fclose(file);
        exit(1);
    }
    line[strcspn(line, "\r\n")] = 0;
    if (strncmp(line, "key: \"", 6) != 0) {
        fprintf(stderr, "Loi: Dong thu hai phai bat dau bang 'key: \"'. Noi dung doc duoc: '%s'\n", line);
        fclose(file);
        exit(1);
    }
    if (strlen(line + 6) < 17 || line[6 + 16] != '"') {
        fprintf(stderr, "Loi: Key phai co dung 16 ky tu trong dau ngoac kep, doc duoc: '%s'\n", line + 6);
        fclose(file);
        exit(1);
    }
    strncpy((char *)key, line + 6, 16);
    fclose(file);

    // Mã hóa plaintext
    unsigned char ciphertext[16];
    aes_encrypt(plaintext, ciphertext, key, SIZE_16);

    // Ghi ciphertext vào output.txt
    FILE *outputFile = fopen("output.txt", "w");
    if (!outputFile) {
        fprintf(stderr, "Loi: Khong mo duoc file output.txt\n");
        exit(1);
    }
    fprintf(outputFile, "Ciphertext (HEX format):\n");
    for (int i = 0; i < 16; i++) {
        fprintf(outputFile, "%02x%c", ciphertext[i], ((i + 1) % 16) ? ' ' : '\n');
    }
    fclose(outputFile);

    // Giải mã ciphertext
    unsigned char decryptedtext[16];
    aes_decrypt(ciphertext, decryptedtext, key, SIZE_16);

    // Ghi decryptedtext vào decrypt.txt
    FILE *decryptFile = fopen("decrypt.txt", "w");
    if (!decryptFile) {
        fprintf(stderr, "Loi: Khong mo duoc file decrypt.txt\n");
        exit(1);
    }
    fprintf(decryptFile, "Decrypted text (HEX format):\n");
    for (int i = 0; i < 16; i++) {
        fprintf(decryptFile, "%02x%c", decryptedtext[i], ((i + 1) % 16) ? ' ' : '\n');
    }
    fclose(decryptFile);

    printf("Ma hoa va giai ma hoan tat. Kiem tra output.txt va decrypt.txt\n");

    return 0;
}
 
// Lấy giá trị từ S-Box
unsigned char getSBoxValue(unsigned char num)
{
    return sbox[num];
}
 
// Lấy giá trị từ S-Box ngược
unsigned char getSBoxInvert(unsigned char num)
{
    return rsbox[num];
}

// Xoay trái một word 8 bit
void rotate(unsigned char *word)
{
    unsigned char c;
 
    c = word[0];
    for (int i = 0; i < 3; i++)
        word[i] = word[i + 1];
    word[3] = c;
}
 
// Lấy giá trị từ bảng Rcon
unsigned char getRconValue(unsigned char num)
{
    return Rcon[num];
}
 
// Hàm core cho việc lập lịch khóa
void core(unsigned char *word, int iteration)
{
    // Xoay word sang trái 8 bit
    rotate(word);
 
    // Thay thế tất cả 4 byte của word bằng S-Box
    for (int i = 0; i < 4; ++i)
    {
        word[i] = getSBoxValue(word[i]);
    }
 
    word[0] = word[0] ^ getRconValue(iteration);
}
 
// Mở rộng khóa thành khóa lớn hơn để sử dụng trong các vòng
void expandKey(unsigned char *expandedKey,
               unsigned char *key,
               enum keySize size,
               size_t expandedKeySize)
{
    // Kích thước khóa mở rộng hiện tại (tính bằng byte)
    int currentSize = 0;
    int rconIteration = 1;
    unsigned char t[4] = {0}; // Biến tạm 4 byte
 
    // Gán 16, 24 hoặc 32 byte đầu tiên của khóa mở rộng bằng khóa đầu vào
    for (int i = 0; i < size; i++)
        expandedKey[i] = key[i];
    currentSize += size;
 
    while (currentSize < expandedKeySize)
    {
        // Gán 4 byte trước đó vào biến tạm t
        for (int i = 0; i < 4; i++)
        {
            t[i] = expandedKey[(currentSize - 4) + i];
        }
 
        // Mỗi 16, 24, hoặc 32 byte, áp dụng core schedule và tăng rconIteration
        if (currentSize % size == 0)
        {
            core(t, rconIteration++);
        }
 
        // Với khóa 256-bit, thêm một bước thay thế S-Box
        if (size == SIZE_32 && ((currentSize % size) == 16))
        {
            for (int i = 0; i < 4; i++)
                t[i] = getSBoxValue(t[i]);
        }
 
        // XOR t với block 16, 24, hoặc 32 byte trước đó để tạo 4 byte tiếp theo
        for (int i = 0; i < 4; i++)
        {
            expandedKey[currentSize] = expandedKey[currentSize - size] ^ t[i];
            currentSize++;
        }
    }
}
 
// Thay thế tất cả byte trong state bằng giá trị từ S-Box
void subBytes(unsigned char *state)
{
    for (int i = 0; i < 16; i++)
        state[i] = getSBoxValue(state[i]);
}
 
// Dịch chuyển các hàng trong state
void shiftRows(unsigned char *state)
{
    // Lặp qua 4 hàng và dịch chuyển từng hàng
    for (int i = 0; i < 4; i++)
        shiftRow(state + i * 4, i);
}
 
// Dịch chuyển một hàng cụ thể sang trái
void shiftRow(unsigned char *state, unsigned char nbr)
{
    unsigned char tmp;
    // Dịch hàng sang trái nbr lần
    for (int i = 0; i < nbr; i++)
    {
        tmp = state[0];
        for (int j = 0; j < 3; j++)
            state[j] = state[j + 1];
        state[3] = tmp;
    }
}
 
// Cộng khóa vòng vào state
void addRoundKey(unsigned char *state, unsigned char *roundKey)
{
    for (int i = 0; i < 16; i++)
        state[i] = state[i] ^ roundKey[i];
}
 
// Nhân hai số trong trường Galois
unsigned char galois_multiplication(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    unsigned char counter;
    unsigned char hi_bit_set;
    for (counter = 0; counter < 8; counter++)
    {
        if ((b & 1) == 1)
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}
 
// Trộn các cột trong state
void mixColumns(unsigned char *state)
{
    unsigned char column[4];
 
    // Lặp qua 4 cột
    for (int i = 0; i < 4; i++)
    {
        // Tạo một cột bằng cách lấy giá trị từ 4 hàng
        for (int j = 0; j < 4; j++)
        {
            column[j] = state[(j * 4) + i];
        }
 
        // Trộn cột
        mixColumn(column);
 
        // Đưa giá trị trở lại state
        for (int j = 0; j < 4; j++)
        {
            state[(j * 4) + i] = column[j];
        }
    }
}
 
// Trộn một cột cụ thể
void mixColumn(unsigned char *column)
{
    unsigned char cpy[4];
    for (int i = 0; i < 4; i++)
    {
        cpy[i] = column[i];
    }
    column[0] = galois_multiplication(cpy[0], 2) ^
                galois_multiplication(cpy[3], 1) ^
                galois_multiplication(cpy[2], 1) ^
                galois_multiplication(cpy[1], 3);
 
    column[1] = galois_multiplication(cpy[1], 2) ^
                galois_multiplication(cpy[0], 1) ^
                galois_multiplication(cpy[3], 1) ^
                galois_multiplication(cpy[2], 3);
 
    column[2] = galois_multiplication(cpy[2], 2) ^
                galois_multiplication(cpy[1], 1) ^
                galois_multiplication(cpy[0], 1) ^
                galois_multiplication(cpy[3], 3);
 
    column[3] = galois_multiplication(cpy[3], 2) ^
                galois_multiplication(cpy[2], 1) ^
                galois_multiplication(cpy[1], 1) ^
                galois_multiplication(cpy[0], 3);
}
 
// Thực hiện một vòng mã hóa AES
void aes_round(unsigned char *state, unsigned char *roundKey)
{
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, roundKey);
}
 
// Tạo khóa vòng từ khóa mở rộng
void createRoundKey(unsigned char *expandedKey, unsigned char *roundKey)
{
    // Lặp qua các cột
    for (int i = 0; i < 4; i++)
    {
        // Lặp qua các hàng
        for (int j = 0; j < 4; j++)
            roundKey[(i + (j * 4))] = expandedKey[(i * 4) + j];
    }
}
 
// Thân chính của thuật toán mã hóa AES
void aes_main(unsigned char *state, unsigned char *expandedKey, int nbrRounds)
{
    unsigned char roundKey[16];
 
    createRoundKey(expandedKey, roundKey);
    addRoundKey(state, roundKey);
 
    for (int i = 1; i < nbrRounds; i++)
    {
        createRoundKey(expandedKey + 16 * i, roundKey);
        aes_round(state, roundKey);
    }
 
    createRoundKey(expandedKey + 16 * nbrRounds, roundKey);
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKey);
}
 
// Hàm mã hóa AES
char aes_encrypt(unsigned char *input,
                 unsigned char *output,
                 unsigned char *key,
                 enum keySize size)
{
    // Kích thước khóa mở rộng
    int expandedKeySize;
 
    // Số vòng mã hóa
    int nbrRounds;
 
    // Khóa mở rộng
    unsigned char *expandedKey;
 
    // Khối 128-bit để mã hóa
    unsigned char block[16];
  
    // Xác định số vòng dựa trên kích thước khóa
    switch (size)
    {
    case SIZE_16:
        nbrRounds = 10;
        break;
    case SIZE_24:
        nbrRounds = 12;
        break;
    case SIZE_32:
        nbrRounds = 14;
        break;
    default:
        return ERROR_AES_UNKNOWN_KEYSIZE;
        break;
    }
 
    expandedKeySize = (16 * (nbrRounds + 1));
 
    expandedKey = (unsigned char *)malloc(expandedKeySize * sizeof(unsigned char));
 
    if (expandedKey == NULL)
    {
        return ERROR_MEMORY_ALLOCATION_FAILED;
    }
    else
    {
        // Gán giá trị cho khối từ input
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
                block[(i + (j * 4))] = input[(i * 4) + j];
        }
 
        // Mở rộng khóa
        expandKey(expandedKey, key, size, expandedKeySize);
 
        // Mã hóa khối bằng khóa mở rộng
        aes_main(block, expandedKey, nbrRounds);
 
        // Gán kết quả mã hóa vào output
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
                output[(i * 4) + j] = block[(i + (j * 4))];
        }
 
        // Giải phóng bộ nhớ của khóa mở rộng
        free(expandedKey);
        expandedKey = NULL;
    }
 
    return SUCCESS;
}
 
// Thay thế byte trong state bằng S-Box ngược
void invSubBytes(unsigned char *state)
{
    for (int i = 0; i < 16; i++)
        state[i] = getSBoxInvert(state[i]);
}
 
// Dịch chuyển ngược các hàng trong state
void invShiftRows(unsigned char *state)
{
    // Lặp qua 4 hàng và dịch chuyển ngược từng hàng
    for (int i = 0; i < 4; i++)
        invShiftRow(state + i * 4, i);
}
 
// Dịch chuyển ngược một hàng cụ thể sang phải
void invShiftRow(unsigned char *state, unsigned char nbr)
{
    unsigned char tmp;
    // Dịch hàng sang phải nbr lần
    for (int i = 0; i < nbr; i++)
    {
        tmp = state[3];
        for (int j = 3; j > 0; j--)
            state[j] = state[j - 1];
        state[0] = tmp;
    }
}
 
// Trộn ngược các cột trong state
void invMixColumns(unsigned char *state)
{
    unsigned char column[4];
 
    // Lặp qua 4 cột
    for (int i = 0; i < 4; i++)
    {
        // Tạo một cột từ 4 hàng
        for (int j = 0; j < 4; j++)
        {
            column[j] = state[(j * 4) + i];
        }
 
        // Trộn ngược cột
        invMixColumn(column);
 
        // Đưa giá trị trở lại state
        for (int j = 0; j < 4; j++)
        {
            state[(j * 4) + i] = column[j];
        }
    }
}
 
// Trộn ngược một cột cụ thể
void invMixColumn(unsigned char *column)
{
    unsigned char cpy[4];
    for (int i = 0; i < 4; i++)
    {
        cpy[i] = column[i];
    }
    column[0] = galois_multiplication(cpy[0], 14) ^
                galois_multiplication(cpy[3], 9) ^
                galois_multiplication(cpy[2], 13) ^
                galois_multiplication(cpy[1], 11);
    column[1] = galois_multiplication(cpy[1], 14) ^
                galois_multiplication(cpy[0], 9) ^
                galois_multiplication(cpy[3], 13) ^
                galois_multiplication(cpy[2], 11);
    column[2] = galois_multiplication(cpy[2], 14) ^
                galois_multiplication(cpy[1], 9) ^
                galois_multiplication(cpy[0], 13) ^
                galois_multiplication(cpy[3], 11);
    column[3] = galois_multiplication(cpy[3], 14) ^
                galois_multiplication(cpy[2], 9) ^
                galois_multiplication(cpy[1], 13) ^
                galois_multiplication(cpy[0], 11);
}
 
// Thực hiện một vòng giải mã AES
void aes_invRound(unsigned char *state, unsigned char *roundKey)
{
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, roundKey);
    invMixColumns(state);
}
 
// Thân chính của thuật toán giải mã AES
void aes_invMain(unsigned char *state, unsigned char *expandedKey, int nbrRounds)
{
    unsigned char roundKey[16];
 
    createRoundKey(expandedKey + 16 * nbrRounds, roundKey);
    addRoundKey(state, roundKey);
 
    for (int i = nbrRounds - 1; i > 0; i--)
    {
        createRoundKey(expandedKey + 16 * i, roundKey);
        aes_invRound(state, roundKey);
    }
 
    createRoundKey(expandedKey, roundKey);
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, roundKey);
}
 
// Hàm giải mã AES
char aes_decrypt(unsigned char *input,
                 unsigned char *output,
                 unsigned char *key,
                 enum keySize size)
{
    // Kích thước khóa mở rộng
    int expandedKeySize;
 
    // Số vòng giải mã
    int nbrRounds;
 
    // Khóa mở rộng
    unsigned char *expandedKey;
 
    // Khối 128-bit để giải mã
    unsigned char block[16];
  
    // Xác định số vòng dựa trên kích thước khóa
    switch (size)
    {
    case SIZE_16:
        nbrRounds = 10;
        break;
    case SIZE_24:
        nbrRounds = 12;
        break;
    case SIZE_32:
        nbrRounds = 14;
        break;
    default:
        return ERROR_AES_UNKNOWN_KEYSIZE;
        break;
    }
 
    expandedKeySize = (16 * (nbrRounds + 1));
 
    expandedKey = (unsigned char *)malloc(expandedKeySize * sizeof(unsigned char));
 
    if (expandedKey == NULL)
    {
        return ERROR_MEMORY_ALLOCATION_FAILED;
    }
    else
    {
        // Gán giá trị cho khối từ input
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
                block[(i + (j * 4))] = input[(i * 4) + j];
        }
 
        // Mở rộng khóa
        expandKey(expandedKey, key, size, expandedKeySize);
 
        // Giải mã khối bằng khóa mở rộng
        aes_invMain(block, expandedKey, nbrRounds);
 
        // Gán kết quả giải mã vào output
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
                output[(i * 4) + j] = block[(i + (j * 4))];
        }
 
        // Giải phóng bộ nhớ của khóa mở rộng
        free(expandedKey);
        expandedKey = NULL;
    }
 
    return SUCCESS;
}