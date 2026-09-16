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

Replay dumps sit under `sd:/ultimate/smush_info/replays/{stem}/` using the **Vault filename** (`OpenFile` path). JSON `{stem}.log` stays at `sd:/smush_info/` and gets `replay_file`. Import: copy that inner file into `save_data/replay/` — keep the name. Dump waits for `CloseFile`, skips truncated or missing UTF-16 `"Replay"` + `FRAM`. HID is hooked via `LookupSymbol` + `A64HookFunction` on nnSdk `GetNpadState` / `GetNpadStates`. **Keep** `libnn_hid_hook.nro` if other mods need it — we wrap the same `GetNpadState` symbols (Skyline chains; we mask after their callbacks). **Do not** also install [Auto-Save Replays](https://gamebanana.com/mods/394784) or results-screen-skip (they OR buttons on results and fight this). After results is detected, **mute all pads immediately**, wait **~7.5s**, then tap **A → A → Y → D-pad right → A** on the first full pad (Pro/dual/handheld/GC) (0.34s between taps). Skip (all-pad A) runs after a successful SD dump. If the dump does not land within ~6s (and no vault write is still open), tap **B** and retry the save seq (up to 3 attempts). After 3 misses, **pads go live** so players can skip manually. The save Yes dialog can clear `is_result_mode`; the seq **keeps going** (Skyline log: `is_result_mode false during …, keep seq`). HOME/suspend **pauses** waits; HOME during save **B then retries**. Pad-poll hitches pause the clock; they do not replay A A Y. After a successful SD dump, **delete that Vault file** so NAND does not fill (first save of a session is assumed to have room). Watch `:4242` JSON: `hid_hooks` (0–12), `hid_npad_hits`, `hid_masking`, `hid_elapsed_ms`. HID cancel reasons print on Skyline TCP 6969 (`no dump, B then retry`, `no dump after 3 attempts, pads live`, `HOME resume`, `vault write still open`).

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
