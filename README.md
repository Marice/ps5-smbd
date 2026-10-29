# ps5-smbd

The PS5's `/data` and `/mnt` as Windows shares, from a payload: `\\<ps5-ip>\data` and `\\<ps5-ip>\mnt`,
user `ps5`, password `ps5`, read and write.

Built on [libsmb2](https://github.com/sahlberg/libsmb2)'s SMB2/3 server (LGPL-2.1), pinned to one commit of
master, with the file system behind it in `src/fs.c`.

**Anyone on your network who knows the login can change or delete anything under `/data` and `/mnt`**:
saves, payload settings, passwords other apps keep there.

## Using it

1. Load `ps5-smbd.elf` like any payload (elfldr on port 9021: `nc -w 5 <ps5-ip> 9021 < ps5-smbd.elf`,
   or your payload manager).
2. In Windows: `net use Z: \\<ps5-ip>\data /user:ps5 ps5`, or type `\\<ps5-ip>\data` in Explorer and log in
   as `ps5` / `ps5`.

Typing `\\<ps5-ip>` alone does not list the shares yet; name the share.

## Building

```sh
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make            # ps5-smbd.elf (fetches and builds libsmb2 on the first run)
make host       # the same server on this computer, port 4450, sharing build/data and build/mnt
```

## License

LGPL-2.1-or-later, as libsmb2.
