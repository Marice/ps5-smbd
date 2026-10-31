<p align="center"><img src="docs/media/logo.png" width="520" alt="ps5-smbd, SMB server payload"></p>

# ps5-smbd

The PS5's `/data` and `/mnt` as Windows shares, from a payload: `\\<console>\data` and `\\<console>\mnt`,
user `ps5`, password `ps5`, read and write.

<img src="docs/media/explorer.png" width="523" alt="The console as PS5-832 in Explorer's Network view, its data share open on /data/homebrew">

Built on [libsmb2](https://github.com/sahlberg/libsmb2)'s SMB2/3 server, pinned to one commit of master and
patched (`patches/`), with the file system behind it in `src/fs.c`.

**Anyone on your network who knows the login can change or delete anything under `/data` and `/mnt`**:
saves, payload settings, passwords other apps keep there.

## Using it

1. Load `ps5-smbd.elf` like any payload (elfldr on port 9021: `nc -w 5 <ps5-ip> 9021 < ps5-smbd.elf`,
   or your payload manager). It shows up as `ps5-smbd.elf` in the console's process list.
2. In Windows, any of:
   - the console in Explorer's **Network** view (WS-Discovery);
   - `\\<console name>` in Explorer, the name as set in Settings > System (for example `\\PS5-832`);
   - `\\<ps5-ip>`, which lists the shares;
   - `net use Z: \\<console name>\data /user:ps5 ps5`.

   Log in as `ps5` / `ps5`.

Each drive the console mounts under `/mnt` (the extended storage `ext0`/`ext1`, a USB drive in `usb0` to `usb7`)
is also a share of its own, next to `data` and `mnt`: `\\<console>\ext1`. Copy to a drive through its own share:
Windows asks a share's root for the free space, and under `\\<console>\mnt\ext1` that root is `/mnt`, not the
drive, so a copy there can be refused for want of room. A USB drive plugged in later shows up at the next
connection.

The console answers its name over NetBIOS (UDP 137), LLMNR (UDP 5355) and mDNS (`<name>.local`, UDP 5353),
and announces itself over WS-Discovery (UDP 3702, metadata on TCP 5357). A port that is taken is skipped with
a line in the log; SMB on port 445 runs regardless.

SMB 3.0 to 3.1.1, signed (Windows 11 requires signing and refuses guest logons, hence the login).

## If Windows cannot connect

What ps5-smbd speaks, and what it does not:

| | |
| --- | --- |
| SMB versions | 3.0, 3.0.2 and 3.1.1. Not SMB1 or 2.x. |
| Login | NTLM, user `ps5`, password `ps5`. No guest access, no Kerberos. |
| Signing | Yes (AES-CMAC). |
| Encryption | No. |

Go through these in order:

1. **Is the payload running?** In PowerShell: `Test-NetConnection <ps5-ip> -Port 445`. It must report `TcpTestSucceeded : True`.
2. **Get a clearer error than Explorer's.** In a Command Prompt, run `net use * \\<ps5-ip>\data /user:ps5 ps5`. The number after "System error" tells you more than Explorer does.
3. **Check the SMB settings of your PC.** In PowerShell:
   ```
   Get-SmbClientConfiguration | Select RequireEncryption, Smb2DialectMin, BlockNTLM, RequireSecuritySignature
   ```
   - `RequireEncryption` must be False, because ps5-smbd does not encrypt. With it on, the connection more likely hangs than shows an error. Fix: `Set-SmbClientConfiguration -RequireEncryption $false`.
   - `BlockNTLM` must be False, because ps5-smbd logs in with NTLM. Fix: `Set-SmbClientConfiguration -BlockNTLM $false`.
   - `Smb2DialectMin` may be up to SMB311.
   - `RequireSecuritySignature`: leave it True, the Windows 11 default. When the PC does not require signing, ps5-smbd 0.2.0 and older answered one step of the connection (the negotiate check) unsigned. Windows refuses such an answer, seen as "Invalid signature" (2148073478); error 1208 may be the same thing. From 0.3.0 that answer is always signed.
4. **Clear credentials Windows remembers.** Windows keeps one login per server. Run `net use \\<ps5-ip>\data /delete` (and the same for any other share of the console you have connected), and look at `cmdkey /list` for an old entry for the console's IP or name.
5. **Still stuck? Make a trace.**
   - Create an empty file `/data/ps5-smbd/trace` on the console.
   - Restart the payload, try once, and look in `/data/ps5-smbd/smbd.log`.
   - Remove the `trace` file afterwards, because the trace writes a line for every request.

Errors you may see from `net use`:

| Error | Meaning |
| --- | --- |
| 53 (network path not found) | The PC does not reach port 445 on the console. Check that the payload runs, the IP is right, and nothing in between blocks it. |
| 86, 1326 | Wrong user or password. Use `ps5` / `ps5`. |
| 1219 | Windows already has a connection to the console with other credentials. See step 4. |
| 2148073478 | "Invalid signature": Windows refused part of the server's answer. See step 3. |
| 1208 | A general "extended error". Go through step 3; if that does not help, make a trace (step 5). |

## Logs

- The payload's output goes to the kernel log (klogsrv shows it).
- A crash leaves one line in `/data/ps5-smbd/smbd.log`: `CRASH signal N at ...: rip main+OFFSET`. Look the
  offset up with `nm` on the same build. A stop by a signal (`stopped by signal N`) or a server loop that
  returns leaves a line too; a kill -9 cannot.
- For a full trace of every request, create the file `/data/ps5-smbd/trace` and restart the payload; the
  trace goes to `/data/ps5-smbd/smbd.log`. Remove the file again afterwards: the trace writes a line for
  every request to the SSD.

## Building

```sh
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make            # ps5-smbd.elf (fetches, patches and builds libsmb2 and libdcerpc on the first run)
make host       # the same server on this computer, port 4450, sharing build/data and build/mnt
```

`tools/build-libsmb2.sh` fetches libsmb2's archive of the pinned commit (checked by sha256), applies
`patches/libsmb2-*.patch` and builds both libraries into `.deps/`. To rebuild them after changing a patch,
remove `.deps/ps5/lib/libsmb2.a` (or `.deps/host/...`) first.

The tests in `tests/` are libsmb2 clients run against `make host`:

- `client.c`: write, read, rename, list, delete;
- `shares.c`: the share list, and a drive under mnt as a share of its own;
- `notify.c`: change notify and cancel;
- `preauth.c`: raw requests out of turn: before a login (a cancel, a tree connect, a create first) they drop that client, not the server; after a login, a session setup for a session the connection does not have is answered USER_SESSION_DELETED and the first session goes on, and one for a new session takes the first one's place, whose requests then get USER_SESSION_DELETED;
- `cmac.c`: the signing's AES-CMAC against RFC 4493 and the portable code, over whole messages and in pieces, and its speed;
- `review.c`: what the code review found (pipe rename, failed compounds, wildcards, names that are not UTF-8, unknown set-info classes, FileAllInformation's name).

Libsmb2 itself has to be built with `-fsanitize=address` too for ASan to see its side of a bug.

## License

ps5-smbd's own code is under the GNU General Public License v3.0, see [LICENSE](LICENSE).

The payload links statically with:

- **libsmb2**: LGPL-2.1-or-later ([notice](third_party/libsmb2-COPYING),
  [text](third_party/libsmb2-LICENCE-LGPL-2.1.txt)). The patches in `patches/` are changes to libsmb2 and fall
  under its licence. To build the payload with your own libsmb2, change the commit in
  `tools/build-libsmb2.sh` or add a patch, and run `make`.
- **libdcerpc** from the same tree: BSD-2-Clause, Copyright (C) 2018 Ronnie Sahlberg
  ([notice](third_party/libdcerpc-COPYING)).
