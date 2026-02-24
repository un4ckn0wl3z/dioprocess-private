# Network Test Tools

TCP and UDP client/server tools for testing the DioProcess Packet Capture feature.

**UDP is recommended for testing packet resend** - it's stateless so resent packets work correctly.

## Building

### Option 1: Using build.bat (Recommended)
Open a **Developer Command Prompt** and run:
```cmd
build.bat
```

### Option 2: Using CMake
```cmd
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

### Option 3: Manual compilation
```cmd
cl /EHsc /O2 tcp_server.cpp /Fe:tcp_server.exe /link ws2_32.lib
cl /EHsc /O2 tcp_client.cpp /Fe:tcp_client.exe /link ws2_32.lib
```

## Usage

### 1. Start the Server
```cmd
tcp_server.exe [port]
```
Default port: 12345

The server will display its **PID** - use this in DioProcess Packet Capture.

### 2. Start the Client
```cmd
tcp_client.exe [host] [port]
```
Default: localhost:12345

### 3. Capture Packets
1. Open DioProcess
2. Go to **Packet Capture** tab
3. Enter the server or client **PID**
4. Click **Start**
5. Send messages from the client
6. Watch packets appear in real-time

## Client Commands

| Command | Description |
|---------|-------------|
| `<text>` | Send text message |
| `flood N` | Send N test messages rapidly |
| `binary` | Send 256 bytes of binary data (0x00-0xFF) |
| `quit` | Disconnect |

## Testing Packet Resend

**Use UDP for testing resend** - TCP is stateful and resent packets may be rejected.

### UDP Resend Test (Recommended)
1. Start `udp_server.exe`
2. Start `udp_client.exe` and send a message
3. In DioProcess Packet Capture, enter the server PID and click Start
4. Send more messages from the client
5. Select a captured UDP packet
6. Click **Resend** - the server will receive it as a new message!

### TCP Resend Limitations
TCP packets have sequence numbers. Resent packets will have seq=0 which the TCP stack may reject as out-of-sequence.

## Example Session

**Server:**
```
=== TCP Test Server ===
[*] Server listening on port 12345
[*] PID: 1234 (use this for packet capture)
[*] Waiting for connections...

[+] Client connected: 127.0.0.1:54321

[1] Received 12 bytes:
Text: Hello World!
Hex: 48 65 6C 6C 6F 20 57 6F 72 6C 64 21
[>] Sent echo response (21 bytes)
```

**Client:**
```
=== TCP Test Client ===
[*] PID: 5678 (use this for packet capture)
[*] Connecting to 127.0.0.1:12345...
[+] Connected!

> Hello World!
[>] Sent 12 bytes
[<] Received 21 bytes:
Text: [ECHO #1] Hello World!
```
