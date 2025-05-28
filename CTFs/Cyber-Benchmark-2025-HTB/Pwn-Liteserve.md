`stack-size = 2001194 bytes`

Running `ulimit` on the docker container returns `unlimited` this means threads will have a size of at most, 8MB.

`SO_REUSEADDR` in use, seemingly:

`iVar2 = setsockopt(local_54,1,2,&local_5c,4);` 

The `2` in the third argument might be `SO_REUSEADDR`.

The first `15` bytes from `big_buffer + 1000000`, the first `127` bytes from `big_buffer + 1000016` and the first `15` bytes from `big_buffer + 1000144` are user controllable.

The `url_decode` function will decode the URL in `big_buffer + 1000016` into `big_buffer + 1000160`.

The `parse_headers` function reads the headers it supports and moves them to the following locations (note: it ONLY moves the header values, not the keys):

| Header Name       | Location in `local_big_buffer` | Offset (from `local_big_buffer`) |
| ----------------- | ------------------------------ | -------------------------------- |
| `Host`            | `local_big_buffer + 0xf4384`   | `0xf4384`                        |
| `User-Agent`      | `local_big_buffer + 0xf4404`   | `0xf4404`                        |
| `Accept`          | `local_big_buffer + 0xf4484`   | `0xf4484`                        |
| `Accept-Language` | `local_big_buffer + 0xf4504`   | `0xf4504`                        |
| `Accept-Encoding` | `local_big_buffer + 0xf4584`   | `0xf4584`                        |
| `Connection`      | `local_big_buffer + 0xf4604`   | `0xf4604`                        |

All those locations are contiguous 128 byte buffers. Anything beyond the 128th byte will be discarded.