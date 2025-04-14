# Basic AES Implementation in C

## Mô tả

Đây là một triển khai cơ bản của thuật toán mã hóa AES (Advanced Encryption Standard) bằng ngôn ngữ C. Chương trình đọc plaintext và key từ tệp `input.txt`, mã hóa plaintext bằng AES-128, ghi ciphertext vào `output.txt`, sau đó giải mã ciphertext và ghi kết quả vào `decrypt.txt`. Mã này được thiết kế cho mục đích học tập và không nên sử dụng trong các ứng dụng thực tế.

## Cách sử dụng

1. **Chuẩn bị tệp input.txt:**
   - Dòng 1: `plaintext: "xxxxxxxxxxxxxxxx"` (16 ký tự trong dấu ngoặc kép)
   - Dòng 2: `key: "xxxxxxxxxxxxxxxx"` (16 ký tự trong dấu ngoặc kép)
   
   Ví dụ:
