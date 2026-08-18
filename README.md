# fl_spy

gl_spy enhancement written for fluffer but compatible with glftpd. Improved visibility and overview.

## Build

```bash
make            # needs ncursesw (pkg-config ncursesw)
make install    # → /usr/local/bin/fl_spy
```

## Run

```bash
fl_spy                        # reads /etc/fluffer.conf, else /etc/glftpd.conf
fl_spy -r /path/fluffer.conf  # alternate config
fl_spy -k 0xDEAD              # override the SysV IPC key
```

The config supplies `rootpath`, `datapath`, `ipc_key` and the log paths (`xferlog`, `glftpdlog`, `login_log`, `sysop_log`); everything has glftpd-compatible defaults, so a stock glftpd.conf works too.

## Data sources

- **ONLINE SHM segment** — sessions, live transfer counters. The slot count comes from the segment size (not config), so a max_users mismatch can't skew the view.  The daemon PID is taken from the segment's creator PID; after a daemon restart the tool re-attaches automatically.
- **xferlog tail** — per-user transfer history in the detail overlay. The transfer-time field unit follows the config's `xferlog_millisecs`.
- **glftpd.log + login.log + sysop.log tails** — the activity view (tag column: G/L/S).  Rotation and truncation are handled.

## Views & keys

| Key | Action |
|---|---|
| `1`/`u`, `2`/`t`, `3`/`a`, `Tab` | users / transfers / activity view |
| `Enter` | user detail overlay (fixed-size, framed): sessions pane + transfer history; `Tab` switches pane, arrows scroll the focused one |
| `/` | filter (username; also matched in transfers/log) |
| `s` | cycle sort (speed / name / sessions, or speed / user / elapsed) |
| `g` | toggle bandwidth graph (1 s per column, UP and DN auto-scaled, combined peak in the title; height scales with the terminal, 8–14 rows) |
| `b` | toggle speed units: GiB/s (binary) ↔ bit/s (decimal) |
| `x` / `k` | abort transfer / kick session (y/N confirm) |
| `+` / `-` | refresh rate (100 ms – 2 s) |
| arrows, PgUp/PgDn, Home/End | navigate; in the log view End resumes follow |
| `?` | help, `q`/Esc quit |

## Abort / kick

Uses the daemon's realtime-signal protocol:
`tgkill(shm_cpid, slot.procid, SIGRTMIN)` aborts the current transfer, `SIGRTMIN+1` also kicks the session (see `docs/signals.md` in the fluffer tree).
`procid` is a live TID only while a transfer runs, so both actions are offered mid-transfer only, and you must run fl_spy as the daemon's user or root.

Note: not compatible with glftpd. 
