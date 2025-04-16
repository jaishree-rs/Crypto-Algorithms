#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define MAX 1000

// Convert string to uppercase
void to_uppercase(char *str) {
    for (int i = 0; str[i]; i++)
        str[i] = toupper(str[i]);
}

// Caesar Cipher
void caesar_cipher(char *text, int key, int encrypt) {
    for (int i = 0; text[i]; i++) {
        if (isalpha(text[i])) {
            char base = 'A';
            if (encrypt)
                text[i] = (text[i] - base + key) % 26 + base;
            else
                text[i] = (text[i] - base - key + 26) % 26 + base;
        }
    }
    printf("Result: %s\n", text);
}

// Atbash Cipher
void atbash_cipher(char *text) {
    for (int i = 0; text[i]; i++) {
        if (isalpha(text[i]))
            text[i] = 'Z' - (text[i] - 'A');
    }
    printf("Result: %s\n", text);
}

// August Cipher (like Caesar with fixed shift 1)
void august_cipher_encrypt(char *text) {
    for (int i = 0; text[i]; i++) {
        if (isalpha(text[i]))
            text[i] = (text[i] - 'A' + 1) % 26 + 'A';
    }
    printf("Encrypted Text: %s\n", text);
}

void august_cipher_decrypt(char *text) {
    for (int i = 0; text[i]; i++) {
        if (isalpha(text[i]))
            text[i] = (text[i] - 'A' - 1 + 26) % 26 + 'A';
    }
    printf("Decrypted Text: %s\n", text);
}

// Affine Cipher 
int modInverse(int a, int m) {
    a = a % m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1)
            return x;
    }
    return -1;
}

void affineEncrypt(char* text, int a, int b) {
    printf("Encrypted Text: ");
    for (int i = 0; text[i] != '\0'; i++) {
        char ch = text[i];
        if (isalpha(ch)) {
            if (isupper(ch)) {
                printf("%c", (char)(((a * (ch - 'A') + b) % 26) + 'A'));
            } else {
                printf("%c", (char)(((a * (ch - 'a') + b) % 26) + 'a'));
            }
        } else {
            printf("%c", ch);
        }
    }
    printf("\n");
}

void affineDecrypt(char* text, int a, int b) {
    int a_inv = modInverse(a, 26);
    if (a_inv == -1) {
        printf("Modular inverse doesn't exist for a = %d and modulus = 26\n", a);
        return;
    }

    printf("Decrypted Text: ");
    for (int i = 0; text[i] != '\0'; i++) {
        char ch = text[i];
        if (isalpha(ch)) {
            if (isupper(ch)) {
                int x = a_inv * ((ch - 'A' - b + 26) % 26);
                printf("%c", (char)(x % 26 + 'A'));
            } else {
                int x = a_inv * ((ch - 'a' - b + 26) % 26);
                printf("%c", (char)(x % 26 + 'a'));
            }
        } else {
            printf("%c", ch);
        }
    }
    printf("\n");
}

int gcd(int a, int b) {
    if (b == 0)
        return a;
    return gcd(b, a % b);
}

// Vigenere Cipher
void vigenere_cipher(char *text, char *key, int encrypt) {
    int len = strlen(text), keylen = strlen(key);
    for (int i = 0, j = 0; i < len; i++) {
        if (isalpha(text[i])) {
            int shift = key[j % keylen] - 'A';
            if (encrypt)
                text[i] = (text[i] - 'A' + shift) % 26 + 'A';
            else
                text[i] = (text[i] - 'A' - shift + 26) % 26 + 'A';
            j++;
        }
    }
    printf("Result: %s\n", text);
}

// Gronsfeld Cipher
void gronsfeld(char *text, char *key, int op) {
    int len = strlen(text);
    for (int i = 0, j = 0; i < len; i++) {
        if (isalpha(text[i])) {
            int k = key[j % strlen(key)] - '0';
            if (op == 1)
                text[i] = (text[i] - 'A' + k) % 26 + 'A';
            else
                text[i] = (text[i] - 'A' - k + 26) % 26 + 'A';
            j++;
        }
    }
    printf("Result: %s\n", text);
}

// Beaufort Cipher
void beaufort(char *text, char *key) {
    int len = strlen(text);
    for (int i = 0, j = 0; i < len; i++) {
        if (isalpha(text[i])) {
            int k = key[j % strlen(key)] - 'A';
            text[i] = (k - (text[i] - 'A') + 26) % 26 + 'A';
            j++;
        }
    }
    printf("Result: %s\n", text);
}

void beaufort_decrypt(char *text, char *key) {
    int len = strlen(text);
    int key_len = strlen(key);

    for (int i = 0, j = 0; i < len; i++) {
        if (isalpha(text[i])) {
            char ch = toupper(text[i]); 
            char kch = toupper(key[j % key_len]);

            int pt_char = (kch - ch + 26) % 26 + 'A';
            text[i] = pt_char;

            j++;
        }
    }
    printf("Decrypted text: %s\n", text);
}


// Autokey Cipher
void autokeyEncrypt(char *plaintext, char *key) {
    char full_key[MAX];
    strcpy(full_key, key);
    strcat(full_key, plaintext);  
    
    int pt_len = strlen(plaintext);
    int plain_idx = 0;
    int key_idx = 0;
    char ciphertext[MAX] = "";
    
    while (plain_idx < pt_len) {
        // Skip non-alphabetic characters in plaintext
        if (!isalpha(plaintext[plain_idx])) {
            ciphertext[strlen(ciphertext)] = plaintext[plain_idx];
            plain_idx++;
            continue;
        }
        
        // Skip non-alphabetic characters in key
        if (!isalpha(full_key[key_idx])) {
            key_idx++;
            continue;
        }
        
        // Convert both to lowercase for calculation
        char p = tolower(plaintext[plain_idx]);
        char k = tolower(full_key[key_idx]);
        
        // Encrypt using the formula: (plaintext + key) % 26
        char encrypted = ((p - 'a' + (k - 'a')) % 26) + 'a';
        ciphertext[strlen(ciphertext)] = encrypted;
        
        plain_idx++;
        key_idx++;
    }
    ciphertext[strlen(ciphertext)] = '\0';
    
    printf("Encrypted text: %s\n", ciphertext);
}

void autokeyDecrypt(char *ciphertext, char *key) {
    char full_key[MAX];
    strcpy(full_key, key);
    
    int ct_len = strlen(ciphertext);
    int cipher_idx = 0;
    int key_idx = 0;
    char plaintext[MAX] = "";
    
    while (cipher_idx < ct_len) {
        // Skip non-alphabetic characters in ciphertext
        if (!isalpha(ciphertext[cipher_idx])) {
            plaintext[strlen(plaintext)] = ciphertext[cipher_idx];
            cipher_idx++;
            continue;
        }
        
        // Skip non-alphabetic characters in key
        if (!isalpha(full_key[key_idx])) {
            key_idx++;
            continue;
        }
        
        // Convert both to lowercase for calculation
        char c = tolower(ciphertext[cipher_idx]);
        char k = tolower(full_key[key_idx]);
        
        // Decrypt using the formula: (ciphertext - key + 26) % 26
        char decrypted = ((c - k + 26) % 26) + 'a';
        plaintext[strlen(plaintext)] = decrypted;
        
        // Extend the key with the decrypted character for autokey property
        full_key[strlen(full_key)] = decrypted;
        full_key[strlen(full_key)] = '\0';
        
        cipher_idx++;
        key_idx++;
    }
    plaintext[strlen(plaintext)] = '\0';
    
    printf("Decrypted text: %s\n", plaintext);
}

// Running Key Cipher
void runningKey(char *text, char *key, int op) {
    int len = strlen(text);
    if (strlen(key) < len) {
        printf("Key too short!\n");
        return;
    }
    for (int i = 0, j = 0; i < len; i++) {
        if (isalpha(text[i])) {
            int k = key[j] - 'A';
            if (op == 1)
                text[i] = (text[i] - 'A' + k) % 26 + 'A';
            else
                text[i] = (text[i] - 'A' - k + 26) % 26 + 'A';
            j++;
        }
    }
    printf("Result: %s\n", text);
}

// Hill Cipher (2x2)
int hill_determinant(int** matrix, int n) {
    if (n == 1) return matrix[0][0];
    
    int det = 0;
    // Correctly allocate a 2D array
    int** minor = (int**)malloc((n-1) * sizeof(int*));
    for (int i = 0; i < n-1; i++) {
        minor[i] = (int*)malloc((n-1) * sizeof(int));
    }
    
    for (int i = 0; i < n; i++) {
        for (int j = 1; j < n; j++) {
            for (int k = 0, col = 0; k < n; k++) {
                if (k != i) {
                    minor[j-1][col++] = matrix[j][k];
                }
            }
        }
        int sign = (i % 2 == 0) ? 1 : -1;
        det += sign * matrix[0][i] * hill_determinant(minor, n-1);
    }
    
    for (int i = 0; i < n-1; i++) {
        free(minor[i]);
    }
    free(minor);
    
    return (det % 26 + 26) % 26;
}

// Adjoint matrix calculation for Hill Cipher
void hill_adjoint(int** matrix, int** adj, int n) {
    if (n == 1) {
        adj[0][0] = 1;
        return;
    }
    
    int sign = 1;
    // Correctly allocate a 2D array
    int** temp = (int**)malloc((n-1) * sizeof(int*));
    for (int i = 0; i < n-1; i++) {
        temp[i] = (int*)malloc((n-1) * sizeof(int));
    }
    
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            // Get cofactor
            int row_idx = 0;
            for (int row = 0; row < n; row++) {
                if (row == i) continue;
                
                int col_idx = 0;
                for (int col = 0; col < n; col++) {
                    if (col == j) continue;
                    temp[row_idx][col_idx++] = matrix[row][col];
                }
                row_idx++;
            }
            
            // Sign of adj[j][i] positive if sum of row and column indexes is even
            sign = ((i+j) % 2 == 0) ? 1 : -1;
            
            // Interchange rows and columns to get the transpose of the cofactor matrix
            adj[j][i] = (sign * hill_determinant(temp, n-1) + 26) % 26;
        }
    }
    
    for (int i = 0; i < n-1; i++) {
        free(temp[i]);
    }
    free(temp);
}

// Modular inverse for Hill Cipher
int hill_modInverse(int a) {
    for (int i = 1; i < 26; i++) {
        if ((a * i) % 26 == 1) {
            return i;
        }
    }
    return -1; // No modular inverse exists
}

// Matrix multiplication for Hill Cipher
void hill_multiplyMatrix(int** key, int* block, int* result, int n) {
    for (int i = 0; i < n; i++) {
        result[i] = 0;
        for (int j = 0; j < n; j++) {
            result[i] += key[i][j] * block[j];
        }
        result[i] = result[i] % 26;
    }
}

// Main Hill Cipher function
void hill_cipher(char* text, int n, int** key, int encrypt) {
    int len = strlen(text);
    
    // Pad text with 'X' if needed
    int padding = len % n;
    if (padding != 0) {
        padding = n - padding;
        for (int i = 0; i < padding; i++) {
            text[len + i] = 'X';
        }
        text[len + padding] = '\0';
        len += padding;
    }
    
    if (!encrypt) {
        int det = hill_determinant(key, n);
        int modInv = hill_modInverse(det);
        
        if (modInv == -1) {
            printf("Key matrix is not invertible. Cannot decrypt.\n");
            return;
        }
        
        // Correctly allocate a 2D array
        int** adj = (int**)malloc(n * sizeof(int*));
        for (int i = 0; i < n; i++) {
            adj[i] = (int*)malloc(n * sizeof(int));
        }
        
        hill_adjoint(key, adj, n);
        
        // Calculate inverse key
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                key[i][j] = (adj[i][j] * modInv) % 26;
            }
        }
        
        for (int i = 0; i < n; i++) {
            free(adj[i]);
        }
        free(adj);
    }
    
    // Process text in blocks of size n
    for (int i = 0; i < len; i += n) {
        int* block = (int*)malloc(n * sizeof(int));
        int* result = (int*)malloc(n * sizeof(int));
        
        for (int j = 0; j < n; j++) {
            block[j] = text[i + j] - 'A';
        }
        
        hill_multiplyMatrix(key, block, result, n);
        
        for (int j = 0; j < n; j++) {
            text[i + j] = result[j] + 'A';
        }
        
        free(block);
        free(result);
    }
    
    printf("Result: %s\n", text);
}

void removeSpaces(char* str) {
    int i, j = 0;
    for (i = 0; str[i]; i++) {
        if (str[i] != ' ')
            str[j++] = str[i];
    }
    str[j] = '\0';
}

//Railfence Cipher
void railFenceEncrypt(char* plaintext, int key) {
    removeSpaces(plaintext);
    int len = strlen(plaintext);
    char rail[key][len];
    for (int i = 0; i < key; i++)
        for (int j = 0; j < len; j++)
            rail[i][j] = '\n';

    int row = 0, dir_down = 0;
    for (int i = 0; i < len; i++) {
        if (row == 0 || row == key - 1)
            dir_down = !dir_down;

        rail[row][i] = plaintext[i];
        row += dir_down ? 1 : -1;
    }

    printf("Encrypted text: ");
    for (int i = 0; i < key; i++)
        for (int j = 0; j < len; j++)
            if (rail[i][j] != '\n')
                printf("%c", rail[i][j]);
    printf("\n");
}

void railFenceDecrypt(char* cipher, int key) {
    int len = strlen(cipher);
    char rail[key][len];
    for (int i = 0; i < key; i++)
        for (int j = 0; j < len; j++)
            rail[i][j] = '\n';

    int row = 0, col = 0;
    int dir_down;

    for (int i = 0; i < len; i++) {
        if (row == 0)
            dir_down = 1;
        if (row == key - 1)
            dir_down = 0;
        rail[row][col++] = '*';
        row += dir_down ? 1 : -1;
    }

    int index = 0;
    for (int i = 0; i < key; i++) {
        for (int j = 0; j < len; j++) {
            if (rail[i][j] == '*' && index < len)
                rail[i][j] = cipher[index++];
        }
    }

    // Read in zigzag
    row = 0, col = 0;
    dir_down = 0;
    printf("Decrypted text: ");
    for (int i = 0; i < len; i++) {
        if (row == 0)
            dir_down = 1;
        if (row == key - 1)
            dir_down = 0;
        if (rail[row][col] != '\n')
            printf("%c", rail[row][col++]);
        row += dir_down ? 1 : -1;
    }
    printf("\n");
}

//N-Gram
void ngram_operation(char *text, int n) {
    int len = strlen(text);
    if (len < n) {
        printf("Text is too short for the specified N-Gram size.\n");
        return;
    }

    printf("N-Grams (size %d):\n", n);
    for (int i = 0; i <= len - n; i++) {
        for (int j = i; j < i + n; j++) {
            printf("%c", text[j]);
        }
        printf("\n");
    }
}

//Route Cipher
void route_cipher_encrypt(char *text, int rows, int cols, int clockwise) {
    int len = strlen(text);
    int matrixSize = rows * cols;
    
    // If text is shorter than matrix size, pad with 'X'
    if (len < matrixSize) {
        for (int i = len; i < matrixSize; i++) {
            text[i] = 'X';
        }
        text[matrixSize] = '\0';
    } else if (len > matrixSize) {
        // Truncate text if it's longer than matrix size
        text[matrixSize] = '\0';
    }
    
    // Allocate matrix
    char **matrix = (char**)malloc(rows * sizeof(char*));
    for (int i = 0; i < rows; i++) {
        matrix[i] = (char*)malloc(cols * sizeof(char));
    }
    
    // Fill matrix column by column (vertical filling)
    int index = 0;
    for (int j = 0; j < cols; j++) {
        for (int i = 0; i < rows; i++) {
            if (index < matrixSize) {
                matrix[i][j] = text[index++];
            } else {
                matrix[i][j] = 'X'; 
            }
        }
    }
    
    // Print the matrix for visualization
    printf("\nMatrix arrangement:\n");
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            printf("%c ", matrix[i][j]);
        }
        printf("\n");
    }
    
    // Read in spiral order (clockwise or anti-clockwise)
    printf("\nEncrypted text: ");
    
    int top = 0, right = cols-1, bottom = rows-1, left = 0;
    char result[MAX] = "";
    int resultIndex = 0;
    
    if (clockwise) {
        // Clockwise spiral
        while (top <= bottom && left <= right) {
            // Top row
            for (int i = left; i <= right; i++) {
                result[resultIndex++] = matrix[top][i];
            }
            top++;
            
            // Right column
            for (int i = top; i <= bottom; i++) {
                result[resultIndex++] = matrix[i][right];
            }
            right--;
            
            // Bottom row
            if (top <= bottom) {
                for (int i = right; i >= left; i--) {
                    result[resultIndex++] = matrix[bottom][i];
                }
                bottom--;
            }
            
            // Left column
            if (left <= right) {
                for (int i = bottom; i >= top; i--) {
                    result[resultIndex++] = matrix[i][left];
                }
                left++;
            }
        }
    } else {
        // Anti-clockwise spiral
        while (top <= bottom && left <= right) {
            // Top row
            for (int i = right; i >= left; i--) {
                result[resultIndex++] = matrix[top][i];
            }
            top++;
            
            // Left column
            for (int i = top; i <= bottom; i++) {
                result[resultIndex++] = matrix[i][left];
            }
            left++;
            
            // Bottom row
            if (top <= bottom) {
                for (int i = left; i <= right; i++) {
                    result[resultIndex++] = matrix[bottom][i];
                }
                bottom--;
            }
            
            // Right column
            if (left <= right) {
                for (int i = bottom; i >= top; i--) {
                    result[resultIndex++] = matrix[i][right];
                }
                right--;
            }
        }
    }
    
    result[resultIndex] = '\0';
    printf("%s\n", result);
    
    // Free allocated memory
    for (int i = 0; i < rows; i++) {
        free(matrix[i]);
    }
    free(matrix);
}

// Function to decrypt using Route Cipher
void route_cipher_decrypt(char *text, int rows, int cols, int clockwise) {
    int len = strlen(text);
    int matrixSize = rows * cols;
    
    // Ensure the text length matches the matrix size
    if (len > matrixSize) {
        text[matrixSize] = '\0';
        len = matrixSize;
    }
    
    // Allocate and initialize matrix with placeholder characters
    char **matrix = (char**)malloc(rows * sizeof(char*));
    for (int i = 0; i < rows; i++) {
        matrix[i] = (char*)malloc(cols * sizeof(char));
        for (int j = 0; j < cols; j++) {
            matrix[i][j] = ' '; // Initialize with spaces
        }
    }
    
    // Fill matrix in spiral order according to the direction
    int top = 0, right = cols-1, bottom = rows-1, left = 0;
    int index = 0;
    
    if (clockwise) {
        // Clockwise spiral filling
        while (index < len && top <= bottom && left <= right) {
            // Top row
            for (int i = left; i <= right && index < len; i++) {
                matrix[top][i] = text[index++];
            }
            top++;
            
            // Right column
            for (int i = top; i <= bottom && index < len; i++) {
                matrix[i][right] = text[index++];
            }
            right--;
            
            // Bottom row
            if (top <= bottom) {
                for (int i = right; i >= left && index < len; i--) {
                    matrix[bottom][i] = text[index++];
                }
                bottom--;
            }
            
            // Left column
            if (left <= right) {
                for (int i = bottom; i >= top && index < len; i--) {
                    matrix[i][left] = text[index++];
                }
                left++;
            }
        }
    } else {
        // Anti-clockwise spiral filling
        while (index < len && top <= bottom && left <= right) {
            // Top row
            for (int i = right; i >= left && index < len; i--) {
                matrix[top][i] = text[index++];
            }
            top++;
            
            // Left column
            for (int i = top; i <= bottom && index < len; i++) {
                matrix[i][left] = text[index++];
            }
            left++;
            
            // Bottom row
            if (top <= bottom) {
                for (int i = left; i <= right && index < len; i++) {
                    matrix[bottom][i] = text[index++];
                }
                bottom--;
            }
            
            // Right column
            if (left <= right) {
                for (int i = bottom; i >= top && index < len; i--) {
                    matrix[i][right] = text[index++];
                }
                right--;
            }
        }
    }
    
    // Print the matrix for visualization
    printf("\nMatrix arrangement after decryption:\n");
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            printf("%c ", matrix[i][j]);
        }
        printf("\n");
    }
    
    // Read column by column to get the original text
    printf("\nDecrypted text: ");
    char result[MAX] = "";
    int resultIndex = 0;
    
    for (int j = 0; j < cols; j++) {
        for (int i = 0; i < rows; i++) {
            if (matrix[i][j] != ' ') {
                result[resultIndex++] = matrix[i][j];
            }
        }
    }
    
    result[resultIndex] = '\0';
    printf("%s\n", result);
    
    // Free allocated memory
    for (int i = 0; i < rows; i++) {
        free(matrix[i]);
    }
    free(matrix);
}

// Function to assign numerical ranks to key characters based on alphabetical order
void remove_whitespace(char *input, char *output) {
    int j = 0;
    for (int i = 0; input[i]; i++) {
        if (!isspace(input[i])) {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

// Function to assign numerical ranks to key characters based on alphabetical order
void assign_ranks(char *key, int *ranks) {
    // Create a copy of the key for sorting
    char sorted_key[MAX];
    strcpy(sorted_key, key);
    int key_len = strlen(key);
    
    // Simple bubble sort to sort the key
    for (int i = 0; i < key_len - 1; i++) {
        for (int j = 0; j < key_len - i - 1; j++) {
            if (sorted_key[j] > sorted_key[j + 1]) {
                char temp = sorted_key[j];
                sorted_key[j] = sorted_key[j + 1];
                sorted_key[j + 1] = temp;
            }
        }
    }
    
    // Remove duplicates
    int unique_len = 1;
    for (int i = 1; i < key_len; i++) {
        if (sorted_key[i] != sorted_key[unique_len - 1]) {
            sorted_key[unique_len++] = sorted_key[i];
        }
    }
    sorted_key[unique_len] = '\0';
    
    // Assign ranks to each character in original key
    for (int i = 0; i < key_len; i++) {
        for (int j = 0; j < unique_len; j++) {
            if (key[i] == sorted_key[j]) {
                ranks[i] = j + 1;
                break;
            }
        }
    }
}

// Function to encrypt using Myszkowiski Cipher
// Updated Function to encrypt using Myszkowski Cipher with fixed same-rank processing
void myszkowiski_encrypt(char *plaintext, char *key) {
    int key_len = strlen(key);

    // Remove spaces from plaintext
    char text_no_spaces[MAX];
    remove_whitespace(plaintext, text_no_spaces);

    int text_len = strlen(text_no_spaces);

    // Calculate number of rows
    int rows = (text_len + key_len - 1) / key_len;

    // Create the matrix
    char matrix[MAX][MAX];

    // Fill the matrix row by row with padding 'X'
    int idx = 0;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < key_len; j++) {
            if (idx < text_len) {
                matrix[i][j] = text_no_spaces[idx++];
            } else {
                matrix[i][j] = 'X';
            }
        }
    }

    // Assign ranks to the key
    int ranks[MAX];
    assign_ranks(key, ranks);

    // Debug: Print matrix with headers
    printf("\nKey: %s\n", key);
    printf("Ranks: ");
    for (int i = 0; i < key_len; i++) {
        printf("%d ", ranks[i]);
    }
    printf("\n\nMatrix:\n");
    for (int i = 0; i < key_len; i++) {
        printf("%c ", key[i]);
    }
    printf("\n");
    for (int i = 0; i < key_len; i++) {
        printf("%d ", ranks[i]);
    }
    printf("\n");
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < key_len; j++) {
            printf("%c ", matrix[i][j]);
        }
        printf("\n");
    }

    // Build ciphertext row by row for each rank group
    char ciphertext[MAX];
    int ct_idx = 0;

    // Find maximum rank
    int max_rank = 0;
    for (int i = 0; i < key_len; i++) {
        if (ranks[i] > max_rank) {
            max_rank = ranks[i];
        }
    }

    // Process ranks in order
    for (int rank = 1; rank <= max_rank; rank++) {
        // For each row, pick characters in columns with current rank
        for (int row = 0; row < rows; row++) {
            for (int col = 0; col < key_len; col++) {
                if (ranks[col] == rank) {
                    ciphertext[ct_idx++] = matrix[row][col];
                }
            }
        }
    }

    ciphertext[ct_idx] = '\0';

    printf("\nEncrypted text: %s\n", ciphertext);
}


// decrypt using Myszkowiski Cipher
void myszkowiski_decrypt(char *ciphertext, char *key) {
    int key_len = strlen(key);
    int text_len = strlen(ciphertext);
    int rows = (text_len + key_len - 1) / key_len;

    // Assign ranks to the key
    int ranks[MAX];
    assign_ranks(key, ranks);

    // Create the matrix and fill with placeholders
    char matrix[MAX][MAX];

    // Count how many columns per rank
    int rank_count[MAX] = {0};
    int max_rank = 0;
    for (int i = 0; i < key_len; i++) {
        rank_count[ranks[i]]++;
        if (ranks[i] > max_rank) max_rank = ranks[i];
    }

    // Count how many cells are needed for each rank (row-wise filling)
    int cells_needed[MAX] = {0};
    for (int rank = 1; rank <= max_rank; rank++) {
        cells_needed[rank] = rank_count[rank] * rows;
    }

    // Fill matrix columns row-wise by rank group
    int idx = 0;
    for (int rank = 1; rank <= max_rank; rank++) {
        for (int row = 0; row < rows; row++) {
            for (int col = 0; col < key_len; col++) {
                if (ranks[col] == rank) {
                    if (idx < text_len) {
                        matrix[row][col] = ciphertext[idx++];
                    } else {
                        matrix[row][col] = 'X'; // padding if needed
                    }
                }
            }
        }
    }

    // Reconstruct plaintext from the matrix row-wise
    char plaintext[MAX];
    int pt_idx = 0;
    for (int row = 0; row < rows; row++) {
        for (int col = 0; col < key_len; col++) {
            plaintext[pt_idx++] = matrix[row][col];
        }
    }

    plaintext[pt_idx] = '\0';

    printf("\nDecrypted text: %s\n", plaintext);
}



// Main Menu
int main() {
    char text[MAX], key[MAX];
    int choice, operation, a, b;

    while (1) {
        printf("\n--- Classical Cipher Algorithms ---\n");
        printf("1. Caesar Cipher\n2. Atbash Cipher\n3. August Cipher\n4. Affine Cipher\n5. Vigenere Cipher\n6. Gronsfeld Cipher\n7. Beaufort Cipher\n8. Autokey Cipher\n9. Running Key Cipher\n10. Hill Cipher\n11. Rail Fence Cipher\n12. N-Gram Operations\n13. Route Cipher\n14. Myszkowiski Cipher\n0. Exit\nChoose an option: ");
        scanf("%d", &choice);
        getchar();

        if (choice == 0) break;

        printf("Enter the text: ");
        fgets(text, MAX, stdin);
        text[strcspn(text, "\n")] = 0;
        to_uppercase(text);

        switch (choice) {
            case 1:
                printf("Enter key (shift): ");
                scanf("%d", &a);
                printf("1. Encrypt\n2. Decrypt: ");
                scanf("%d", &operation);
                caesar_cipher(text, a, operation == 1);
                break;

            case 2:
                atbash_cipher(text);
                break;

            case 3:
                printf("1. Encrypt\n2. Decrypt: ");
                scanf("%d", &operation);
                if (operation == 1)
                    august_cipher_encrypt(text);
                else
                    august_cipher_decrypt(text);
                break;

            case 4: {
                int a, b;
                printf("Enter 'a' (must be coprime with 26): ");
                scanf("%d", &a);
                if (gcd(a, 26) != 1) {
                    printf("Invalid 'a'. Must be coprime with 26.\n");
                    break;
                }
                printf("Enter 'b': ");
                scanf("%d", &b);
                getchar();
                printf("1. Encrypt\n2. Decrypt: ");
                scanf("%d", &operation);
                getchar();
                if (operation == 1)
                    affineEncrypt(text, a, b);
                else
                    affineDecrypt(text, a, b);
                break;
            }

            case 5:
                printf("Enter key: ");
                scanf("%s", key);
                to_uppercase(key);
                printf("1. Encrypt\n2. Decrypt: ");
                scanf("%d", &operation);
                vigenere_cipher(text, key, operation == 1);
                break;

            case 6:
                printf("Enter numeric key (e.g. 123): ");
                scanf("%s", key);
                printf("1. Encrypt\n2. Decrypt: ");
                scanf("%d", &operation);
                gronsfeld(text, key, operation);
                break;

            case 7: {
                printf("1. Encrypt\n2. Decrypt: ");
                scanf("%d", &operation);
                getchar(); 
            
                printf("Enter key: ");
                fgets(key, MAX, stdin);
                key[strcspn(key, "\n")] = 0;
                to_uppercase(key);
            
                if (operation == 1)
                    beaufort(text, key);
                else if (operation == 2)
                    beaufort_decrypt(text, key);
                else
                    printf("Invalid operation.\n");
                break;
            }

            case 8:
                printf("Enter key: ");
                fgets(key, MAX, stdin);
                key[strcspn(key, "\n")] = 0;  
                
                printf("1. Encrypt\n2. Decrypt: ");
                scanf("%d", &operation);
                getchar();  
                
                if (operation == 1)
                    autokeyEncrypt(text, key);
                else if (operation == 2)
                    autokeyDecrypt(text, key);
                else
                    printf("Invalid operation.\n");
                break;

            case 9:
                printf("Enter key (same length as text): ");
                scanf("%s", key);
                to_uppercase(key);
                printf("1. Encrypt\n2. Decrypt: ");
                scanf("%d", &operation);
                runningKey(text, key, operation);
                break;

            case 10: {
                int n;
                printf("\nEnter dimension of key matrix (e.g., 2 for 2x2, 3 for 3x3): ");
                scanf("%d", &n);
                
                // Clear input buffer
                int c;
                while ((c = getchar()) != '\n' && c != EOF);
                
                if (n <= 0) {
                    printf("Invalid dimension.\n");
                    break;
                }
                
                // Allocate memory for key matrix (corrected)
                int** keyMatrix = (int**)malloc(n * sizeof(int*));
                for (int i = 0; i < n; i++) {
                    keyMatrix[i] = (int*)malloc(n * sizeof(int));
                }
                
                printf("\nEnter your key matrix elements:\n");
                
                // Input the matrix row by row
                for (int i = 0; i < n; i++) {
                    printf("Enter values for row %d (separate by spaces): ", i+1);
                    for (int j = 0; j < n; j++) {
                        if (scanf("%d", &keyMatrix[i][j]) != 1) {
                            printf("Error: Invalid input. Please enter integers only.\n");
                            // Clear input buffer
                            while ((c = getchar()) != '\n' && c != EOF);
                            j--; 
                            continue;
                        }
                        // Ensure values are in valid range
                        keyMatrix[i][j] = ((keyMatrix[i][j] % 26) + 26) % 26;
                    }
                    // Clear any remaining characters
                    while ((c = getchar()) != '\n' && c != EOF);
                }
                
                printf("\nYour key matrix is:\n");
                for (int i = 0; i < n; i++) {
                    printf("  ");
                    for (int j = 0; j < n; j++) {
                        printf("%2d ", keyMatrix[i][j]);
                    }
                    printf("\n");
                }
                
                printf("\n1. Encrypt\n2. Decrypt\nEnter your choice: ");
                scanf("%d", &operation);
                
                // Clear input buffer
                while ((c = getchar()) != '\n' && c != EOF);
                
                hill_cipher(text, n, keyMatrix, operation == 1);
                
                // Free allocated memory
                for (int i = 0; i < n; i++) {
                    free(keyMatrix[i]);
                }
                free(keyMatrix);
                break;
            }
            
            case 11: {
                printf("Rail Fence Cipher Selected\n");
                printf("1. Encryption\n2. Decryption\n");
                scanf("%d", &operation);
                printf("Enter key (number of rails): ");
                scanf("%d", &a); // reuse 'a' for key
                if (operation == 1)
                    railFenceEncrypt(text, a);
                else
                    railFenceDecrypt(text, a);
                break;
            }
            
            case 12:{
                printf("Enter N for N-Gram operation: ");
                int n;
                scanf("%d", &n);
                ngram_operation(text, n);
                break;
            }
            
            case 13: {
                int rows, cols, direction;
                printf("Enter number of rows: ");
                scanf("%d", &rows);
                printf("Enter number of columns: ");
                scanf("%d", &cols);
                printf("Route direction:\n1. Clockwise\n2. Anti-clockwise\nEnter choice: ");
                scanf("%d", &direction);
                
                // Clear input buffer
                int c;
                while ((c = getchar()) != '\n' && c != EOF);
                
                printf("1. Encrypt\n2. Decrypt\nEnter your choice: ");
                scanf("%d", &operation);
                
                // Clear input buffer again
                while ((c = getchar()) != '\n' && c != EOF);
                
                if (operation == 1) {
                    route_cipher_encrypt(text, rows, cols, direction == 1);
                } else if (operation == 2) {
                    route_cipher_decrypt(text, rows, cols, direction == 1);
                } else {
                    printf("Invalid operation.\n");
                }
                break;
            }
            
            case 14: {
                printf("Enter key: ");
                scanf("%s", key);
                to_uppercase(key);
                getchar(); 
                
                printf("1. Encrypt\n2. Decrypt\nEnter your choice: ");
                scanf("%d", &operation);
                getchar(); 
                
                if (operation == 1) {
                    myszkowiski_encrypt(text, key);
                } else if (operation == 2) {
                    myszkowiski_decrypt(text, key);
                } else {
                    printf("Invalid operation.\n");
                }
                break;
            }

            default:
                printf("Invalid option.\n");
        }
    }

    return 0;
}
