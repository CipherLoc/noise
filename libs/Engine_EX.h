//
//  Engine_EX.hpp
//  engineUnitTest
//
//  Created by Scott Combs on 8/17/20.
//  Copyright © 2020 CipherLoc Corporation. All rights reserved.
//

#ifndef Engine_EX_hpp
#define Engine_EX_hpp

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 Encrypts a character buffer to an output buffer using a string as the key

 * @param key - An unsigned char* up to 32 characters
 * @param keyLength - the length of the characters in the key
 * @param input - An unsigned char* of data to encrypt
 * @param inputLength - the length of the characters in the input
 * @param output - A pointer to a pointer for IN/OUT for the ciphertext produced
 * @param outputLength - The length of the output characters of the ciphertext
 produced

 Example:
 * @code
 #define MAXBUFFERSIZE 1000000

 // SET THE KEY
 std::string _key = "maryhadalittlela";
 std::vector<unsigned char> key;
 key.resize(_key.size();
 std::memcpy(key.data(), _key.data(), _key.size());

 // SET THE INPUT
 std::string _input = "Text to encrypt.";
 std::vector<unsigned char> input;
 input.resize(_input.size());
 std::memcpy(input.data(), _input.data(), _input.size());

 // PREPARE THE OUTPUT
 unsigned char* _output = new unsigned char[MAXBUFFERSIZE];
 unsigned char** output = &_output;
 uint64_t outputLength = 0;

 encryptText_EX(key.data(), key.size(), input.data(), input.size(), output,
 outputLength);

 delete _output;

 // THE CIPHERTEXT IS IN THE OUTPUT
 // AND THE LENGTH OF IT IS IN THE OUTPUTLENGTH
 */
// EXPORT void EncryptText_EX(unsigned char *key, uint64_t keyLength,
//                            unsigned char *input, uint64_t inputLength,
//                            unsigned char **output, uint64_t &outputLength);

/**
 Encrypts a character buffer to an output buffer using a string as the key and
 allows setting the FRAGMENT_SIZE and REDUNDANCY

 * @param key - An unsigned char* up to 32 characters
 * @param keyLength - the length of the characters in the key
 * @param input - An unsigned char* of data to encrypt
 * @param inputLength - the length of the characters in the input
 * @param output - A pointer to a pointer for IN/OUT for the ciphertext produced
 * @param outputLength - The length of the output characters of the ciphertext
 produced
 * @param frag - A value 1-n that will split the input buffer into smaller parts
 for processing.
 * @param redun - A value 1-n that will set the unicity value. Smaller number
 mean more shards, larger values mean less shards.

 Example:
 * @code
 #define MAXBUFFERSIZE 1000000

 // SET THE KEY
 std::string _key = "maryhadalittlela";
 std::vector<unsigned char> key;
 key.resize(_key.size();
 std::memcpy(key.data(), _key.data(), _key.size());

 // SET THE INPUT
 std::string _input = "Text to encrypt.";
 std::vector<unsigned char> input;
 input.resize(_input.size());
 std::memcpy(input.data(), _input.data(), _input.size());

 // PREPARE THE OUTPUT
 unsigned char* _output = new unsigned char[MAXBUFFERSIZE];
 unsigned char** output = &_output;
 uint64_t outputLength = 0;
 uint64_t frag = 393216;
 uint64_t redun = frag / 8;
 // Redundancy values less than 1/8 of frag will increase sharding

 encryptBytes_EX(key.data(), key.size(), input.data(), input.size(), output,
 outputLength, fraq, redun);

 delete _output;

 // THE CIPHERTEXT IS IN THE OUTPUT
 // AND THE LENGTH OF IT IS IN THE OUTPUTLENGTH
*/
// EXPORT void encryptBytes_EX(unsigned char *key, uint64_t keyLength,
//                             unsigned char *input, uint64_t inputLength,
//                             unsigned char **output, uint64_t &outputLength,
//                             uint64_t frag = 393216, uint64_t redun = 49152);

/**
 Converts ciphertext to a numerical string

 * @param input - An unsigned char* of ciphertext
 * @param inputLength - the length of the characters in the input
 * @param output - A pointer to a pointer for IN/OUT for the numerical string
 produced
 * @param outputLength - The length of the output characters of the ciphertext
 produced

 Example:
 * @code
    // See encryptText_EX for obtaining the output
    // and outputLength for this input and inputLength.

    // PREPARE THE OUTPUT
    char* _output;
    char** output = &_output;
    uint64_t outputLength = 0;

    DataToString(input, inputLength, output, outputLength);

    // THE _OUTPUT POINTER CONTAINS THE NUMERICAL STRING
    // THE LENGTH OF _OUTPUT IS OUTPUTLENGTH
    // _OUTPUT MUST BE DELETED TO NOT LEAK MEMORY
    delete[] _output;
 */
// EXPORT void DataToString(unsigned char *input, uint64_t inputLength,
//                          char **output, uint64_t &outputLength);

/**
 Decrypts a character buffer to an output buffer using a string as the key

 * @param key - An unsigned char* up to 32 characters
 * @param keyLength - the length of the characters in the key
 * @param input - An unsigned char* of data to decrypt
 * @param inputLength - the length of the characters in the input
 * @param output - A pointer to a pointer for IN/OUT for the deciphered text
 * @param outputLength - The length of the output characters of the deciphered
 text

 Example:
 * @code
 #define MAXBUFFERSIZE 1000000

 // SET THE KEY
 std::string _key = "maryhadalittlela";
 std::vector<unsigned char> key;
 key.resize(_key.size();
 std::memcpy(key.data(), _key.data(), _key.size());

 // SET THE INPUT
 std::string _input = "Text to encrypt.";
 std::vector<unsigned char> input;
 input.resize(_input.size());
 std::memcpy(input.data(), _input.data(), _input.size());

 // PREPARE THE OUTPUT
 unsigned char* _output = new unsigned char[MAXBUFFERSIZE];
 unsigned char** output = &_output;
 uint64_t outputLength = 0;

 decryptText_EX(key.data(), key.size(), input.data(), input.size(), output,
 outputLength);

 // THE DECIPHERED TEXT IS IN THE OUTPUT
 // AND THE LENGTH OF IT IS IN THE OUTPUTLENGTH
 */
// EXPORT void EncryptText_EX(unsigned char *key, uint64_t keyLength,
//                            unsigned char *input, uint64_t inputLength,
//                            unsigned char **output, uint64_t &outputLength);

EXPORT void EncryptText_GO(unsigned char *key, uint64_t keyLength,
                           unsigned char *input, uint64_t inputLength,
                           unsigned char *output, uint64_t *outputLength);

// Synonym of decryptText_EX to compliment encryptBytes_EX
// EXPORT void decryptBytes_EX(unsigned char *key, uint64_t keyLength,
//                             unsigned char *input, uint64_t inputLength,
//                             unsigned char **output, uint64_t &outputLength);

// EXPORT void DecryptText_EX(unsigned char *key, uint64_t keyLength,
//                            unsigned char *input, uint64_t inputLength,
//                            unsigned char **output, uint64_t &outputLength);

EXPORT void DecryptText_GO(unsigned char *key, uint64_t keyLength,
                           unsigned char *input, uint64_t inputLength,
                           unsigned char *output, uint64_t *outputLength);

/**
 Converts a numerical string to ciphered text

 * @param input - An unsigned char* of a numerical string
 * @param output - A pointer to a pointer for IN/OUT for the deciphered text
 * @param outputLength - The length of the output characters of the deciphered
 text

 Example:
 * @code
    // See decryptText_EX for obtaining the output
    // and outputLength for this input and inputLength.

    // PREPARE THE OUTPUT
    char* _output;
    char** output = &_output;
    uint64_t outputLength = 0;

    StringToData(input, inputLength, output, outputLength);

    // THE _OUTPUT POINTER CONTAINS THE DECIPHERED TEXT
    // THE LENGTH OF _OUTPUT IS OUTPUTLENGTH
    // _OUTPUT MUST BE DELETED TO NOT LEAK MEMORY
    delete[] _output;
 */
// EXPORT void StringToData(const char *input, unsigned char **output,
//                          uint64_t &outputLength);

/**
 Encrypts an input file to an output file using a string as the key

 * @param key - An unsigned char* up to 32 characters
 * @param keyLength - the length of the characters in the key
 * @param input - An unsigned char* of the input path and file name to encrypt
 * @param inputLength - the length of the characters in the input path and file
 name
 * @param output - A pointer to a pointer for IN/OUT for the encrypted output
 path and file name
 * @param outputLength - The length of the encrypted output path and file name

 Example:
 * @code
 #define MAXBUFFERSIZE 1000000

 // SET THE KEY
 std::string _key = "maryhadalittlela";
 std::vector<unsigned char> key;
 key.resize(_key.size();
 std::memcpy(key.data(), _key.data(), _key.size());

 // SET THE INPUT
 // DMCG - SET THE INPUT to a file path and name to encrypt
 std::string _input = "";
 std::vector<unsigned char> input;
 input.resize(_input.size());
 std::memcpy(input.data(), _input.data(), _input.size());

 // PREPARE THE OUTPUT
 unsigned char* _output = new unsigned char[MAXBUFFERSIZE];
 unsigned char** output = &_output;
 uint64_t outputLength = 0;

 encryptText_EX(input.data(), input.size(), output, outputLength, key.data(),
 key.size());

 // THE CIPHERTEXT IS IN THE OUTPUT FILE
 // AND THE LENGTH OF IT IS IN THE OUTPUTLENGTH
 */
// EXPORT bool encryptFile_EX(unsigned char *input, uint64_t inputLength,
//                            unsigned char *output, uint64_t outputLength,
//                            unsigned char *key, uint64_t keyLength);

/**
 Encrypts an input file to an output file using a string as the key

 * @param input - An unsigned char* of the input path and file name to decrypt
 * @param inputLength - the length of the characters in the input path and file
 name
 * @param output - A pointer to a pointer for IN/OUT for the decrypted output
 path and file name
 * @param outputLength - The length of the decrypted output path and file name
 * @param key - An unsigned char* up to 32 characters
 * @param keyLength - the length of the characters in the key

 Example:
 * @code
 #define MAXBUFFERSIZE 1000000

 // SET THE KEY
 std::string _key = "maryhadalittlela";
 std::vector<unsigned char> key;
 key.resize(_key.size();
 std::memcpy(key.data(), _key.data(), _key.size());

 // SET THE INPUT
 // DMCG - SET THE INPUT to a file path and name to decrypt
 std::string _input = "";
 std::vector<unsigned char> input;
 input.resize(_input.size());
 std::memcpy(input.data(), _input.data(), _input.size());

 // PREPARE THE OUTPUT
 unsigned char* _output = new unsigned char[MAXBUFFERSIZE];
 unsigned char** output = &_output;
 uint64_t outputLength = 0;

 decryptFile_EX(input.data(), input.size(), output, outputLength, key.data(),
 key.size());

 // THE DECIPHERED TEXT IS IN THE OUTPUT FILE
 // AND THE LENGTH OF IT IS IN THE OUTPUTLENGTH
 */
// EXPORT bool decryptFile_EX(unsigned char *input, uint64_t inputLength,
//                            unsigned char *output, uint64_t outputLength,
//                            unsigned char *key, uint64_t keyLength);

#ifdef __cplusplus
}
#endif

#endif /* Engine_EX_hpp */
