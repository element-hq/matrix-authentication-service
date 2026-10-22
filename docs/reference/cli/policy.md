# `policy`

Global options:
- `--config <config>`: Path to the configuration file.
- `--help`: Print help.

## `policy precompile <input> <output>`

Compile a WASM policy ahead of time.
Loading a precompiled policy skips compiling it at startup, which saves startup time and around 10 MiB of memory.

```console
$ mas-cli policy precompile policy.wasm policy.cwasm
INFO mas_cli::commands::policy:63 Policy precompiled input=policy.wasm output=policy.cwasm size=976528
```

It also writes the SHA-256 digest of the input next to the output, as `<output>.source.sha256` (`policy.cwasm.source.sha256` above).

The output can be used as the [`policy.wasm_module`](../configuration.md#policy).
It can also be put as `policy.cwasm` next to the default `policy.wasm`, along with its `policy.cwasm.source.sha256`: MAS then loads it instead of compiling `policy.wasm`, as long as the digest matches `policy.wasm`.

It only works:
- with the exact same version of MAS as the one that produced it, so it must be regenerated on every upgrade;
- on the same architecture and operating system: run the command with the binary that will load the policy, for example in the same container image;
- on CPUs that support the baseline features of the architecture (`x86-64-v2` on `x86_64`), which the MAS binary needs anyway.
