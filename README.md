# Smush Info (sharlot fork)

A Skyline plugin that hosts a TCP server for subscribing to information about the current Smash Ultimate match. Useful for statistics, game integration, and more.

I have tacked a whole bunch of stuff onto this for [ssbu-stream-automation](https://github.com/sticks-stuff/ssbu-stream-automation). Not my best code but it works.

Original Authors:
* jam1garner
* jugeeya

Seems jam1garner has left the scene so I don't feel particularly comfortable asking them licensing questions, but consider everything I've added to this project GPLv3

# Requirements
smush_info requires you to have the following Skyline plugins downloaded and installed:
- [Arcropolis](https://github.com/Raytwo/ARCropolis/releases)
- [Smashline V2](https://github.com/HDR-Development/smashline/releases) (`libsmashline_plugin.nro`)
- [libnro_hook](https://github.com/ultimate-research/nro-hook-plugin/releases)

Do not install `libacmd_hook.nro` alongside Smashline; both hook ACMD dispatch and will crash when loading a match.

Replay dumps sit under `sd:/ultimate/smush_info/replays/{stem}/` using the **Vault filename** (`OpenFile` path). JSON `{stem}.log` is written beside the vault file in that same folder and gets `replay_file`. Import: copy that inner file into `save_data/replay/` — keep the name. Dump waits for `CloseFile`, skips truncated or missing UTF-16 `"Replay"` + `FRAM`. HID is hooked via `LookupSymbol` + `A64HookFunction` on nnSdk `GetNpadState` / `GetNpadStates`. **Keep** `libnn_hid_hook.nro` if other mods need it — we wrap the same `GetNpadState` symbols (Skyline chains; we mask after their callbacks). **Do not** also install [Auto-Save Replays](https://gamebanana.com/mods/394784) or results-screen-skip (they OR buttons on results and fight this). After results is detected, **mute all pads immediately**, wait **~7.5s**, then tap **A → A → Y → D-pad right → A** on the save pad (0.34s between taps). Skip (all-pad A) runs after a successful SD dump. If the dump does not land within ~6s (and no vault write is still open), tap **B** and retry the save seq (up to 3 attempts). After 3 misses, **pads go live** so players can skip manually. The save Yes dialog can clear `is_result_mode`; the seq **keeps going** (Skyline log: `is_result_mode false during …, keep seq`). HOME/suspend **pauses** waits; HOME during save **B then retries**. Pad-poll hitches pause the clock; they do not replay A A Y. After a successful SD dump, **delete that Vault file** so NAND does not fill (first save of a session is assumed to have room). A whole results session is capped at 60s; past that pads go live no matter the phase (`giving pads back`).

## Controllers

Each npad keeps a **per-style** connected mask built from the states the game polls (`FullKeyState`, `HandheldState`, `JoyDualState`, `GcState`, `JoyLeftState`, `JoyRightState`) and `NpadAttribute` bit 0. One style must never clear another: a **GameCube** pad is polled as both `Gc` (style bit 5) and `FullKey` — they share a LIFO — and every pad also gets polled as JoyLeft/JoyRight. Collapsing those into one "is it a full pad" bit made GC pads flicker in and out each frame, which restarted the save seq forever and hung results with dead pads.

Save pad pick: first **Pro / dual Joy-Con / handheld / GC**, else a **single Joy-Con**. Taps are remapped per the style being polled:

| Logical | Pro/dual/handheld/GC | Right Joy-Con | Left Joy-Con |
| --- | --- | --- | --- |
| A / B / X / Y | same | same | d-pad Right / Down / Up / Left |
| menu Right | d-pad Right | stick right | stick right |

If that pad disconnects, **re-pick** another. A style bit only clears when the game polls that id with that style and sees "not connected"; a pad that was unplugged or re-paired under another id stops being polled at all, so its bits go stale and the pick would drive a ghost while every real pad sits muted. So: if the game polls other pads 60 times without polling the save pad, **drop it** (`save pad 0x0 not polled for 60 polls, drop`), forget its styles, re-pick, and restart the tap seq on the new pad. If nothing usable is connected, we **do not mute** — pads stay live so players can skip by hand — and the seq starts as soon as a controller shows up (`no controller, wait for one (pads live)`). One HID session per match: once pads go live (dump done, 3 misses, or the 60s cap) nothing re-mutes results until the next match starts, even if `is_result_mode` flickers (save dialog, players poking the menu).

Watch `:4242` JSON: `hid_hooks` (0–12), `hid_npad_hits`, `hid_masking`, `hid_elapsed_ms`. Skyline TCP 6969 prints `N/12 npad hooks installed` at boot, a per-pad style inventory (`pad 0x0 styles pro|gc`) and `save pad 0x0 (…)` when the seq starts, plus cancel reasons (`no dump, B then retry`, `no dump after 3 attempts, pads live`, `HOME resume`, `vault write still open`).

Release zip extracts to SD root:
```
atmosphere/contents/01006A800016E000/romfs/skyline/plugins/libsmush_info.nro
ultimate/smush_info/overrides.toml
```

On boot, plugin reads `sd:/ultimate/smush_info/overrides.toml` if present. Uncomment a flag to disable that feature. Missing file or all flags commented = everything on.

```toml
[smush_info]
disable_list = [
    # "disable_results_log",
    # "disable_replay_save",
    # "disable_results_skip",
]
```

- `disable_results_log` — no `{stem}.log` snapshot
- `disable_replay_save` — no auto save seq, no SD dump, no vault delete
- `disable_results_skip` — no all-pad A exit after save

# How to Build and Install
You must have Rust and Cargo installed. [Click here](https://www.rust-lang.org/tools/install) for instructions on how to install based on your system.

Once those are installed, open your command prompt or terminal and run the following commands
```sh
cargo install cargo-skyline
```

To compile your plugin use the following command in the root of the project (beside the `Cargo.toml` file):
```sh
cargo skyline build --release
```
Then pack SD-root zip:
```sh
bash scripts/package-sd.sh
# Windows: powershell -File scripts/package-sd.ps1
```
Zip is `smush_info-sd.zip`. Extract onto SD root. Later NRO updates: copy plugin only, leave `overrides.toml` alone (re-extract resets flags to commented/on).

NRO alone lives at:
```
target/aarch64-skyline-switch/release/libsmush_info.nro
```
Install path:
```
sd:/atmosphere/contents/01006A800016E000/romfs/skyline/plugins
```

`cargo skyline` can also automate some of this process via FTP. If you have an FTP client on your Switch, you can run:
```sh
cargo skyline set-ip [Switch IP]
# install to the correct plugin folder on the Switch and listen for logs
cargo skyline run 
```
