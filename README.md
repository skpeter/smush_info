# Smush Info (sharlot fork)

A Skyline plugin that hosts a TCP server for subscribing to information about the current Smash Ultimate match. Useful for statistics, game integration, and more.

I have tacked a whole bunch of stuff onto this for [ssbu-stream-automation](https://github.com/sticks-stuff/ssbu-stream-automation). Not my best code but it works.

Original Authors:
* jam1garner
* jugeeya

Seems jam1garner has left the scene so I don't feel particularly comfortable asking them licensing questions, but consider everything I've added to this project GPLv3

## Live socket (TCP `:4242`)

Connect to the Switch on port **4242**. Each line is one JSON `Info` object (see `example.json`).

For **versus 1v1** (including CPUs; not training, FFA, or doubles), each in-game player also carries per-game summary fields that update live and freeze on the results screen:

| Field | Meaning |
| --- | --- |
| `neutral_wins` / `neutral_losses` / `non_killing_wins` | Opening counts |
| `stage_control` | Frames closer to center while both are in neutral |
| `avg_damage_per_opening` | Damage dealt ÷ neutral wins |
| `top_opener` / `top_opener_name` | Most common opening motion (hash40 + sheet name) |
| `avg_death` / `earliest_death` / `latest_death` | Death percents from the sample |
| `damage_dealt` / `damage_taken` | Positive damage deltas only |
| `match_self_destructs` / `stocks_taken` | SDs and stocks taken this game |

Ineligible modes publish zeros. Spirits / Classic / World of Light menu ids are still unknown; if one of those looks like two fighters it may be counted as versus.

If you show these numbers on a stream overlay, credit **Vye** (Vye#0547) and **TheComet** (TheComet#5387).

## Results file

Eligible versus games also write a results snapshot (same `Info` shape) with an extra top-level `openings` object. Keys `"0"` / `"1"` are calculator slots. Each opening row includes `character`, `opener`, `name`, damage bounds, `killed`, and `moves`. Character is captured when the string starts so Pyra↔Mythra mid-match does not rename earlier hits.

# Requirements
smush_info requires you to have the following Skyline plugins downloaded and installed:
- [Arcropolis](https://github.com/Raytwo/ARCropolis/releases)
- [Smashline V2](https://github.com/HDR-Development/smashline/releases) (`libsmashline_plugin.nro`)
- [libnn_hid_hook](https://github.com/jugeeya/nn-hid-hook/releases/tag/beta)
- [libnro_hook](https://github.com/ultimate-research/nro-hook-plugin/releases)

Do not install `libacmd_hook.nro` alongside Smashline; both hook ACMD dispatch and will crash when loading a match.

# How to Build and Install
You must have Rust and Cargo installed. [Click here](https://www.rust-lang.org/tools/install) for instructions on how to install based on your system.

Once those are installed, open your command prompt or terminal and run the following commands
```sh
cargo install cargo-skyline
```

To compile your plugin use the following command in the root of the project (beside the `Cargo.toml` file):
```sh
cargo skyline build
```
Your resulting plugin will be the `.nro` found in the folder
```
[plugin name]/target/aarch64-skyline-switch
```
To install (you must already have skyline installed on your switch), put the plugin on your SD at:
```
sd:/atmosphere/contents/01006A800016E000/romfs/skyline/plugins
```

`cargo skyline` can also automate some of this process via FTP. If you have an FTP client on your Switch, you can run:
```sh
cargo skyline set-ip [Switch IP]
# install to the correct plugin folder on the Switch and listen for logs
cargo skyline run 
```

Host unit tests for the shared crate (path dep, not a workspace member):

```sh
cd smush_info_shared && cargo test --lib
```
