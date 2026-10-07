## Learned User Preferences

- Put generated planning files (office-hours sessions and plans) in `docs/` and leave them uncommitted. `docs/` is gitignored.
- Keep the replay-to-save packager (emulator or Checkpoint import) in its own project. This repo only dumps Vault replay files and match JSON to the SD card.
- When asked to test on a Switch, produce a release NRO with `cargo skyline build --release`, and `smush_info-sd.zip` when the SD layout matters. Local skyline dependencies can lag GitHub Actions.
- Keep `libnn_hid_hook.nro` installed when other mods need it. This plugin chains on the same `GetNpadState` symbols.
- Save replays with the results-screen input macro. Runtime scanning for a vault-save offset was rejected after it took more than one match and crashed on boot.
- Release builds leave `disable_results_log`, `disable_replay_save`, and `disable_results_skip` commented in `overrides.toml` so those features stay on unless a user uncomments them.

## Learned Workspace Facts

- `libsmush_info.nro` is a Skyline plugin for Smash Ultimate title `01006A800016E000`. It requires Arcropolis, Smashline V2 (`libsmashline_plugin.nro`), and libnro_hook.
- Config is `sd:/ultimate/smush_info/overrides.toml`. Replay binaries and `{stem}.log` go under `sd:/ultimate/smush_info/replays/{stem}/`, using the Vault filename, and that directory is created if missing.
- GitHub releases publish `smush_info-sd.zip` for extract-at-SD-root (plugin under `atmosphere/contents/01006A800016E000/romfs/skyline/plugins/`).
- The TCP match server on port 4242 is restarted by a watcher after the game is suspended or the console sleeps. The UDP server recovers on its own.
- Match snapshots use reframed2startgg-style winner detection plus results mode as fallback, with a 2-minute cooldown (`SNAPSHOT_COOLDOWN_TICKS`).
- `player.team` is -1 outside team battle and 0–3 from `TeamModule::team_no` during team battle.
- Dumped replay files must keep the original Vault filename so they can be copied into `save_data/replay/`.
