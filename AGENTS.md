## Learned User Preferences

- Put generated planning files (office-hours sessions and plans) in `docs/` and leave them uncommitted. `docs/` is gitignored.
- Keep the replay-to-save packager (emulator or Checkpoint import) in its own project. This repo only dumps Vault replay files and match JSON to the SD card.
- When asked to test on a Switch, produce a release NRO with `cargo skyline build --release`, and `smush_info-sd.zip` when the SD layout matters. Local skyline dependencies can lag GitHub Actions.
- Keep `libnn_hid_hook.nro` installed when other mods need it. This plugin chains on the same `GetNpadState` symbols.
- Save replays with the results-screen input macro. Skip pulses A for 3 seconds (`HID_EXIT_MS`). An 8-second skip continued into the next screen. Runtime scanning for a vault-save offset was rejected after it took more than one match and crashed on boot.
- Release builds leave `disable_results_log`, `disable_replay_save`, and `disable_results_skip` commented in `overrides.toml` so those features stay on unless a user uncomments them.
- Keep replay and HID edits on `ai_replay-autosave-overrides`. Stats work belongs on branch `stats-port` in the `smush_info-stats-port` worktree, branched from master.
- Build artifacts for other branches by running the Rust workflow from the Actions tab or from another workflow, passing an optional ref.

## Learned Workspace Facts

- `libsmush_info.nro` is a Skyline plugin for Smash Ultimate title `01006A800016E000`. It requires Arcropolis, Smashline V2 (`libsmashline_plugin.nro`), and libnro_hook.
- Config is `sd:/ultimate/smush_info/overrides.toml`. Replay binaries and `{stem}.log` go under `sd:/ultimate/smush_info/replays/{stem}/`, using the Vault filename, and that directory is created if missing.
- GitHub releases publish `smush_info-sd.zip` for extract-at-SD-root (plugin under `atmosphere/contents/01006A800016E000/romfs/skyline/plugins/`).
- The TCP match server on port 4242 is restarted by a watcher after the game is suspended or the console sleeps. The UDP server recovers on its own.
- Match snapshots use reframed2startgg-style winner detection plus results mode as fallback, with a 2-minute cooldown (`SNAPSHOT_COOLDOWN_TICKS`).
- `player.team` is -1 outside team battle and 0–3 from `TeamModule::team_no` during team battle.
- Dumped replay files must keep the original Vault filename so they can be copied into `save_data/replay/`.
- Versus 1v1 stats are on `stats-port`: live summary counters on TCP port 4242, and the opening list only in the results JSON written from the game thread. That 1v1 results write bypasses the 2-minute cooldown; other modes still use it. Eligibility is `is_match`, exactly two fighters, training off, and no Ice Climbers. Results freeze the totals until the next eligible match. Spirits, Classic, and World of Light menu ids are unknown.
- `smush_info_shared` is a path dependency. Test it with `cargo test --lib` inside that directory; `cargo test -p smush_info_shared` from the repo root fails.
- On `stats-port`, push runs upload the Actions artifact `libsmush_info-nro`. Pull-request runs skip the GitHub release upload because the ref is `refs/pull/N/merge`.
- Move names on `stats-port` come from `smush_info_shared/data/move_names.csv`, keyed by character plus hash. The table is built on the first real lookup, on the game thread, which hitches the first hit of a session.
