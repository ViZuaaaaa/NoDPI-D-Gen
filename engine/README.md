# DGen Engine work (internal)

Goal: move “smart auto-selection” and strategy profiles **into DGen.exe** (anti-copy / reduce plain-text strategy leakage), while keeping the current “battle machine” behavior stable.

## Folder policy
- `engine/` (this folder) is tracked in git.
- `engine/src/` is **ignored** by default and is intended for **private engine sources** (anti-copy).
  - Put your local engine sources here when working on DGen.exe internals.

## Current plan (incremental)
1) **Profiles in DGen.exe**: embed a small set of strategy profiles inside the engine and expose `--profile <name>`.
2) **Auto-mode in DGen.exe**: expose `--auto` / `--autopick` that runs internal probes and chooses a profile.
3) **Launcher integration**: launcher becomes a thin UI/wrapper that starts DGen.exe in `--auto` mode and monitors status.

## Build
See `engine/build-dgen.ps1`.

Notes:
- Full anti-copy is impossible on client-side; the goal is to raise the cost of copying and to reduce plain-text strategy leakage.
- If the engine source is committed publicly, anti-copy benefits are limited.
