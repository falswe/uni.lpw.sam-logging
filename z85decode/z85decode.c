#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "z85.h"

/**
 * Print a hex dump of binary data
 *
 * @param data Pointer to binary data
 * @param size Size of the data in bytes
 */
void print_hex_dump(const unsigned char* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        // Print byte in hex format
        printf("%02x ", data[i]);

        // Add a newline every 16 bytes for readability
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }

    // Add final newline if we didn't end on a multiple of 16
    if (size % 16 != 0) {
        printf("\n");
    }
}

int main(int argc, char* argv[]) {
    // Check if we have input
    if (argc < 2) {
        printf("Usage: %s <z85_encoded_string>\n", argv[0]);
        return 1;
    }

    // Get the Z85 encoded string from command line
    const char* encoded = argv[1];
    size_t encoded_len = strlen(encoded);

    // Calculate the maximum possible size of the decoded data
    size_t max_decoded_size = Z85_decode_with_padding_bound(encoded, encoded_len);
    if (max_decoded_size == 0) {
        printf("Error: Invalid Z85 string or padding indicator\n");
        return 1;
    }

    // Add more detailed debugging
    printf("Encoded Z85 string (length %zu):\n%s\n", encoded_len, encoded);
    printf("Padding digit: %c (value: %d)\n", encoded[0], encoded[0] - '0');
    printf("Calculated maximum decoded size: %zu bytes\n", max_decoded_size);

    // Allocate buffer for decoded data
    unsigned char* decoded = (unsigned char*)malloc(max_decoded_size);
    if (!decoded) {
        printf("Error: Memory allocation failed\n");
        return 1;
    }

    // Decode the Z85 data
    size_t decoded_size = Z85_decode_with_padding(encoded, (char*)decoded, encoded_len);
    if (decoded_size == 0) {
        printf("Error: Failed to decode Z85 data\n");
        free(decoded);
        return 1;
    }

    // Print information about the decoded data
    printf("Decoded data (%zu bytes):\n", decoded_size);
    print_hex_dump(decoded, decoded_size);

    // Clean up
    free(decoded);
    return 0;
}