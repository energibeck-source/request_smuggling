# request_smuggling

An HTTP/1.1 and HTTP/2 request-smuggling (desync) scanner written in Go, with
raw-socket request control, a modular set of detection techniques, timing-based
confirmation, and a built-in TUI theory reader.

Because it speaks raw HTTP instead of going through a normal client, it can send
the deliberately malformed and ambiguous requests that desync attacks rely on
(mismatched `Content-Length` / `Transfer-Encoding`, chunk games, HTTP/2 downgrade
abuse) without a library "fixing" them first.

## Techniques

Selectable via `-tech` (comma-separated, or `all`):

- `clte`, `tecl`, `tete` — classic CL.TE / TE.CL / TE.TE desync
- `0cl` — 0.CL desync (timing-based)
- `h2te`, `h2cl`, `h2crlf` — HTTP/2 downgrade smuggling (H2.TE, H2.CL, CRLF injection)

## Install

```
git clone https://github.com/<your-account>/request_smuggling
cd request_smuggling
go build -o gosmuggler .
```

Requires Go 1.25+. `katana` is optional, used only with `-rk` for automatic
sitemap crawling.

## Usage

```
./gosmuggler -u https://target.example
./gosmuggler -u https://target.example -tech clte,tecl,0cl -rl 3
./gosmuggler -f targets.json -w 4
./gosmuggler -theory
```

| Flag          | Description                                               |
|---------------|-----------------------------------------------------------|
| `-u`          | Target URL (`https://host:port/path`)                     |
| `-p`          | Target port (overrides URL port)                          |
| `-f`          | JSON file with a list of targets                          |
| `-tech`       | Techniques: `clte,tecl,tete,0cl,h2te,h2cl,h2crlf,all`     |
| `-s`          | Sitemap file (jsonl) for sitemap-aware modules            |
| `-rk`         | Auto-run katana to build a sitemap                        |
| `-tls`        | TLS impersonation: `default\|chrome\|firefox\|safari\|edge\|random` |
| `-proxy`      | Proxy address (`host:port`)                               |
| `-t`          | Request timeout (default 10s)                             |
| `-delay`      | Delay between modules (default 5s)                        |
| `-rl` / `-rpm`| Rate limit per second / per minute                        |
| `-r`          | Max retries per module (default 3)                        |
| `-w`          | Parallel workers for a target list (default 4)            |
| `-x`          | Exit after the first finding                              |
| `-o`          | Output log file (default `smuggler.log`)                  |
| `-q` / `-v`   | Quiet / verbose                                           |
| `-theory`     | Open the built-in request-smuggling theory reader (TUI)   |
| `-help`       | Show help                                                 |

Optional Telegram reporting: `-tg-report -tg-chat <id>` with the bot token in the
`TELEGRAM_BOT_TOKEN_BASE64` environment variable (base64-encoded).

## Theory reader

`-theory` opens a scrollable TUI reference (`theory.md`) covering how desync arises,
the vulnerability classes, finding/confirming with timing, exploitation, and HTTP/2
specifics. Run it from the repo root so `theory.md` is found.

## Credits

Inspired by the request-smuggling research of **James Kettle** (albinowax) at
PortSwigger — the CL.TE / TE.CL foundations, HTTP/2 desync, browser-powered
desync, and 0.CL ("HTTP/1.1 Must Die") work.

## Legal

For authorized testing only. Use it against systems you own or are explicitly
permitted to test (for example, a bug-bounty program's in-scope assets). You are
responsible for how you use it.

## License

MIT — see [LICENSE](LICENSE).
