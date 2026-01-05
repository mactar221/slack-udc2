#pragma once
#include "common.h"

#pragma optimize("", off)
static int secureMemCopy(void* dest, SIZE_T destSize, const void* src, SIZE_T copySize) {
    const char* srcPtr;
    SIZE_T          i;
    char* destPtr;

    if (!dest || !src || copySize == 0) {
        return UDC2_ERROR_INVALID_PARAM;
    }

    if (copySize > destSize) {
        return UDC2_ERROR_INVALID_PARAM;
    }

    destPtr = (char*)dest;
    srcPtr = (const char*)src;

    for (i = 0; i < copySize; i++) {
        destPtr[i] = srcPtr[i];
    }

    return UDC2_SUCCESS;
}
#pragma optimize("", on)

/**
 * @brief String comparison
 * @param s1 First string to compare
 * @param s2 Second string to compare with first
 * @return 0 if strings are equal
 */
static int strCompare(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

/**
 * @brief Parameter validation
 * @param buffer Buffer pointer to validate
 * @param length Length of the buffer to validate
 * @param checkOutput Whether to validate the output parameter
 * @param output Output parameter pointer to validate if checkOutput is TRUE
 * @return UDC2_SUCCESS on validation success, UDC2_ERROR_INVALID_PARAM on validation failure
 **/

 // Helper to convert integer to string safely within a buffer
static int custom_itoa(int value, char* str, int size) {
    char temp[12]; // Sufficient for 32-bit int including sign
    int i = 0, j = 0;
    unsigned int uvalue;

    if (value < 0) {
        if (size > 1) {
            *str++ = '-';
            size--;
            j++;
        }
        uvalue = (unsigned int)-value;
    }
    else {
        uvalue = (unsigned int)value;
    }

    // Build string in reverse
    do {
        if (i < sizeof(temp)) temp[i++] = (uvalue % 10) + '0';
        uvalue /= 10;
    } while (uvalue > 0);

    // Reverse into destination
    while (i > 0 && size > 1) {
        *str++ = temp[--i];
        size--;
        j++;
    }
    *str = '\0';
    return j;
}

int mini_snprintf(char* buffer, size_t limit, const char* format, ...) {
    va_list args;
    va_start(args, format);

    size_t n = 0;
    while (*format && n < limit - 1) {
        if (*format == '%' && *(format + 1)) {
            format++;
            if (*format == 's') {
                const char* s = va_arg(args, const char*);
                while (s && *s && n < limit - 1) {
                    buffer[n++] = *s++;
                }
            }
            else if (*format == 'd') {
                int d = va_arg(args, int);
                n += custom_itoa(d, &buffer[n], (int)(limit - n));
            }
            else if (*format == '%') {
                buffer[n++] = '%';
            }
            format++;
        }
        else {
            buffer[n++] = *format++;
        }
    }

    if (limit > 0) buffer[n] = '\0';
    va_end(args);
    return (int)n;
}

size_t mini_strlen(const char* s) {
    size_t len = 0;
    while (s[len] != '\0') {
        len++;
    }
    return len;
}

char* mini_strchr(const char* s, int c) {
    while (*s != (char)c) {
        if (!*s) return NULL;
        s++;
    }
    return (char*)s;
}

char* mini_strncpy(char* dest, const char* src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}

char* mini_strstr(const char* haystack, const char* needle) {
    if (!*needle) return (char*)haystack;

    for (; *haystack; haystack++) {
        if (*haystack == *needle) {
            const char* h = haystack;
            const char* n = needle;
            while (*h && *n && *h == *n) {
                h++;
                n++;
            }
            if (!*n) return (char*)haystack;
        }
    }
    return NULL;
}

void* mini_memcpy(void* dest, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;

    while (n--) {
        *d++ = *s++;
    }

    return dest;
}

#define snprintf mini_snprintf
#define strlen  mini_strlen
#define strstr  mini_strstr
#define strchr  mini_strchr
#define memcpy  mini_memcpy
#define strncpy mini_strncpy

static int validateParameters(const void* buffer, int length, BOOL checkOutput, void** output) {
    if (!buffer) {
        return UDC2_ERROR_INVALID_PARAM;
    }

    if (length <= 0 || length > MAX_FRAME_SIZE) {
        return UDC2_ERROR_INVALID_PARAM;
    }

    if (checkOutput && !output) {
        return UDC2_ERROR_INVALID_PARAM;
    }

    return UDC2_SUCCESS;
}

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int Base64Decode(const char* in, unsigned char* out, int out_max) {
    int len = (int)mini_strlen(in);
    int i, j = 0;
    int v;

    for (i = 0; i < len && j < out_max; i += 4) {
        v = base64_decode_char(in[i]) << 18;
        v += base64_decode_char(in[i + 1]) << 12;
        if (in[i + 2] != '=') v += base64_decode_char(in[i + 2]) << 6;
        if (in[i + 3] != '=') v += base64_decode_char(in[i + 3]);

        out[j++] = (v >> 16) & 0xFF;
        if (in[i + 2] != '=' && j < out_max) out[j++] = (v >> 8) & 0xFF;
        if (in[i + 3] != '=' && j < out_max) out[j++] = v & 0xFF;
    }
    return j;
}