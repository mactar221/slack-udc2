# Slack UDC2 BOF

A Beacon Object File (BOF) implementation that provides an UDC2 channel that uses Slack API requests.

## Overview

The Slack UDC2 BOF acts as a communication proxy that encapsulates Beacon traffic within Slack API requests.

![image-6](https://github.com/user-attachments/assets/99410863-bcbc-4d0e-b6e3-15b54c6ff7c6)

## Features

### BOF Compliance
- **No MSVCRT Dependencies**: Uses only Windows API functions
- **Minimal Footprint**: Optimized for in-memory execution

## Slack UDC2 Release Example Quick Start Guide

To quickly get the Slack UDC2 Release BOF built and usable within Cobalt Strike, follow the instructions below. Note that you should have the `Release` solution configuration selected for this.

1. In the slack_udc2_bof.cpp file, find the following line: 
```c
        gUdc2State.botToken = "xoxb-TOKEN-HERE"; // SET THIS TO YOUR BOT TOKEN
        gUdc2State.clientchannelId = "CLIENT-CHANNEL-TOKEN-HERE"; // SET THIS TO YOUR SLACK CLIENT CHANNEL ID
        gUdc2State.serverchannelId = "SERVER-CHANNEL-TOKEN-HERE"; // SET THIS TO YOUR SLACK SERVER CHANNEL ID
```
2. Change the values to your configurations.
3. Make sure the "Release" configuration is selected in Visual Studio and choose the architecture you wish to build the BOF for (x64 or x86)
4. From the Build menu in Visual Studio, click Build Solution
5. Once the BOF has been successfully built, open the Cobalt Strike client and open the listeners page. Create a new UDC2 listener. Give it a name like udc2-slack-x64 or udc2-slack-x86 and choose a port for the UDC2 listener to listen on. For the UDC2 BOF field, click on the open-file dialog option and select the Slack UDC2 BOF that you just built in the previous step. Ensure that the "Debug only" checkbox is **NOT** checked. If you want to apply guard rails, apply them, and finally click Save.
6. For specific usage instructions of the Slack UDC2 server python script, refer to the documentation in the server\\README.md file. In the interim, run the python script with the following options: `python3 slack_udc2_server.py --ts-addr YOUR_TS_UDC2_LISTENER_IP --ts-port YOUR_TS_UDC2_LISTENER_PORT`

7. Before running the server, make sure to replace the following values as well (line 24-26):  
```python
    slack_token: str = 'xoxb-TOKEN-HERE'
    slack_client_channel: str = 'REPLACE-TOKEN'
    slack_server_channel: str = 'REPLACE-TOKEN'
```
7. From the Cobalt Strike client, export a payload as you would normally, but choose the new UDC2 listener you created in step 5.
8. Your payload is now ready to execute with the Slack UDC2 BOF stomped into it. Run the payload and you should see Slack API requests being sent to your python UDC2 server which will extract the Beacon frame data from them and forward it on to the UDC2 listener on the Team Server. 
9. You should now see a new Beacon registered in the Cobalt Strike client.

## Architecture

### Core Components

#### Global State Management
```cpp
typedef struct {
    BOOL    initialized;
    UINT32  beaconId; // not used
    const char* botToken;
    const char* clientchannelId;
    const char* serverchannelId;
} UDC2_STATE;
```

## API Reference

### Core Functions

#### `int udc2Proxy(const char* sendBuf, int sendBufLen, char* recvBuf, int recvBufMaxLen)`
Main proxy function for relaying Beacon traffic. This is where the Slack communication happens.

**Parameters:**
- `sendBuf`: Points to Beacon frame data that needs to be sent out
- `sendBufLen`: The total length of the frame data
- `recvBuf`: Points to Beacon memory that you should copy response frame data to
- `recvBufMaxLen`: The max size of the recv buffer

**Returns:** Number of bytes received on success, negative error code on failure

#### `void udc2Close()`
Cleanup function for session termination.

#### `int sendSlackPackets(sendBuf, sendBufLen);`
Send data via Slack so the server will relay it to Teamserver.

**Parameters:**
- `buffer`: Data buffer to send
- `length`: Length of data


## Error Handling

### Error Codes
```cpp
#define UDC2_SUCCESS                 0   // Operation successful
#define UDC2_ERROR_INVALID_PARAM    -1   // Invalid parameter
#define UDC2_ERROR_MEMORY_ALLOC     -2   // Memory allocation failure  
#define UDC2_ERROR_NETWORK          -3   // Network operation failure
#define UDC2_ERROR_TIMEOUT          -4   // Operation timeout
#define UDC2_ERROR_PROTOCOL         -5   // Protocol violation
#define UDC2_ERROR_FRAGMENTATION    -6   // Fragmentation error
```

## Dependencies

### Windows APIs
- **KERNEL32.dll**: Memory management (`HeapAlloc`, `HeapFree`, `GetProcessHeap`)  
- **WS2_32.dll**: Network utilities (`inet_addr`)  
- **Wininet.dll**: network utilities (`InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA`, `InternetReadFile`, `InternetCloseHandle`)

## Limitations

This project is intentionally simplified for educational purposes to help others learn how the UDC2 framework operates. As such, it has the following limitations:  
- **No Fragmentation Support**: Unlike the original Slack implementation, this BOF does not support fragmented transfers. Slack has a limitation of approximately 40,000 characters per message. Attempting to transfer data exceeding this limit will result in an error or unintentional behavior, which may cause the Beacon to crash.  
- **Single Beacon Support**: There is currently no beaconId validation/routing logic implemented in the transport layer. This project supports only one active UDC2 Beacon at a time. Note: While child beacons (SMB/TCP) can be established through the initial Slack-linked beacon, the Slack channel itself cannot distinguish between multiple primary UDC2 beacons.  
- **Infrastructure**: Further development is required for use in a full-scale Red Team engagement, specifically data fragmentation, and multi-beacon management.  

## References

- [ICMP Bof Github](https://github.com/Cobalt-Strike/icmp-udc2)  
- [Cobalt Strike Documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm)
- [BOF Development Guide](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm)

## Author  
Kleiton Kurti ([@kleiton0x00](https://github.com/kleiton0x00))
