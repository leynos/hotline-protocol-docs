# C15 read-only seed configuration diagnosis

At clean private mxd `cb907885cc2a61df2d708f38a3cf42da85c2a016`, the
one C14 seed command exited 1 with `mxd-wireframe-server failed: missing
password`. No `fixture.sqlite` file was created. Its selected file was the
mode-0600 owned `seed.toml`, containing only `[cmds.create-user]` and a
random password; this note does not reproduce that value.

The built `mxd-wireframe-server` delegates to `wireframe::run()`, whose
`load_cli()` uses `AppConfig::load_from_iter` for top-level settings and then
`admin::run_command()` for the parsed `create-user` subcommand. The latter
calls `ortho_config::load_and_merge_subcommand_for::<CreateUserArgs>`. In
installed `ortho_config 0.10.0`, that helper calls
`load_file_and_env_defaults_at()` with a file context rooted at `.` and a
process-backed environment. Its `candidate_paths_at()` searches HOME
`.mxd.toml`, XDG `mxd/config.toml`, and current-directory `.mxd.toml`; it does
**not** inspect `MXD_CONFIG_PATH`. The top-level `AppConfig` did honour the
selected `seed.toml`, but the subcommand helper did not search that name, so
`run_create_user` received `password=None` and returned before opening the
database.

The existing precedence integration test
`tests/create_user_password_precedence.rs` puts the file credential in
`HOME/.mxd.toml`, then proves the subcommand file layer; it separately proves
that `MXD_CMDS_CREATE_USER_PASSWORD` is a supported environment fallback.
These results explain why the first proposed file shape was insufficient for
the actual runtime path. The environment alternative would be read by the
same installed helper, but it would expose the plaintext to the process
environment and is unnecessary here.

**Proposed one-time correction, pending supervisor approval:** copy the
existing random `[cmds.create-user]` content, without displaying it, into a
new mode-0600 `$FIXTURE/home/.mxd.toml`. Keep the owned HOME/XDG directories,
`env -i`, `MXD_CONFIG_PATH=$FIXTURE/seed.toml`, absolute SQLite path, fixed
username, and built binary unchanged. Recheck that the new HOME file is the
only discovered candidate and that SQLite remains absent; run exactly one
new seed process with separate `seed-retry` command/log/exit files. A success
must be followed by a read-only SQLite integrity check and a users-table
query showing exactly one `mxd-peer-c14` row. On any mismatch, stop without
further attempts. The failed first attempt remains retained as evidence.

No second seed, build, database, daemon, namespace entry, or client traffic
was performed during C15.
