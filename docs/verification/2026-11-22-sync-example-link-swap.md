# The sync-folder example and an entry swapped after it was listed

Date: 2026-11-22. Base: `main` at `bed66d4`. Engine: YARA-X 1.23.0, Python 3.12.3, x86_64
Linux container running as root. Rules: a disposable copy of the shipped `rules/local` (89
rules), no vendor packs; every sync folder, outside directory, and gate home was disposable
and under the session scratchpad. Every run below is a direct run on this container; nothing
here is hosted CI. The files hold one line of ordinary text.

## The lead

[#322](https://github.com/cgfixit/yara-gate/issues/322), item 1.
`docs/examples/sync_folder_gate.py` decides what an entry is with `lstat` in `_skip_reason`,
then reads it by name: `path.stat()`, `source.stat()`, and `source.open("rb")` all follow a
link. Between the two, an entry can be replaced. Whoever can write to the sync folder (another
account on the machine, or a collaborator whose client syncs links as links) can put a link
there after the check, and the script copies what the link points at into
`allowed/<sha256>/`, which is the one place the consumer reads.

## Reproduced on the base

A sync folder with `note.txt`, `other.txt`, an injected `inject.md`, and a link that was
there from the start; `--policy agent-ingest`. `_settled` is wrapped so the swap happens
after `_skip_reason` has looked and before the copy, which is one point inside the window.
Each case ran in its own process with a 45 s limit.

| Swap after the listing | Base `bed66d4` | Change |
| --- | --- | --- |
| none | `note.txt` allowed, `inject.md` held, the old link skipped | the same |
| `note.txt` becomes a link to a file outside the folder | **the outside file is in `allowed/` as `note.txt`** | `skip ... link or other entry in its place; not read`; nothing copied |
| `sub/` becomes a link to an outside directory that holds a `note.txt` | **the outside file is in `allowed/`** | the same skip; nothing copied |
| `note.txt` becomes a FIFO | **the run hangs** in `open`; killed at 45 s | the same skip; the run finishes |
| `note.txt` is removed | **`FileNotFoundError`**, the run dies before it withdraws stale copies | `skip ... vanished`; the run finishes |
| `note.txt` is replaced by another regular file | the new file is allowed | the same |

The change's column is the same with the script's Windows path forced on this machine
(`_OPEN_BENEATH = False`).

## The change

- `_open_source` opens the sync folder, then each directory down to the file from the one
  before it with `O_NOFOLLOW` and `dir_fd`, then the file the same way with `O_NONBLOCK`. A
  link at any step is `ELOOP` or `ENOTDIR` and becomes a logged skip.
- `_stage` takes the file type, size, and times from that descriptor before and after the
  copy, so the bytes, the 100 MiB bound, and the changed-during-copy test all describe one
  open file.
- `main` and `_settled` use `lstat`, and a file that vanished is a skip.
- Without `O_NOFOLLOW` and `dir_fd` (Windows): the entry is refused from its `lstat`, opened,
  required to be the same file as the one checked, and its resolved path must still be inside
  the sync folder.

What a listed regular file gets is unchanged: staged, scanned, allowed or held, ledgered.

## Checks

- `tests/test_sync_folder_gate.py` is new: four swaps on each of the two code paths, and a
  settled regular file that is still allowed. 9 passed on the change. Against the base
  example the two link swaps and the removal fail, and the FIFO case was left out because it
  does not return.
- `tests/test_pre_read_hook.py` already held two tests of `_stage`. Both now pass the sync
  folder as its first argument. The growing-source test used to grow the file after
  `Path.stat`; `_stage` no longer sizes the source by name, so the test grows it after the
  descriptor's size is read. Both keep their assertions (`file exceeds 100MB`, nothing left
  in staging), and the file gives 24 passed.
- `ruff check`, `ruff format --check .`, `mypy --strict src scripts`,
  `docs/verification/check_doc_links.py`, and `docs/verification/check_text_controls.py`
  pass.

## What this does not cover

- **Windows.** The second path ran on Linux with the flag forced, not on Windows. There the
  check and the open are two steps, and a swap between them is caught only when the opened
  file differs from the one checked or resolves outside the folder. A junction swapped in
  and back inside that moment is not excluded.
- **A hard link.** A second name for a file the attacker could already read is a regular
  file with two links. The gate's own intake refuses those; this example does not, because a
  sync client can legitimately keep them.
- **How a sync client writes.** Whether Dropbox, OneDrive, or iCloud Drive ever replaces a
  file with a link on their own was not measured.
- **The files a consumer already read.** A copy admitted before this change from a swapped
  entry stays in `allowed/` until its source changes or the detector identity does.
