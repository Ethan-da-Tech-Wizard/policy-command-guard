# Policy Command Guard

A Python project for evaluating shell command strings against a command policy. The evaluator returns an allow or deny decision; it does not itself execute the supplied command.

## What's included

- `policy_guard/engine.py` contains the evaluator and its command and path checks.
- `policy_guard/cli.py` provides a command-line interface with optional JSON output.
- `policy_guard/policy.toml` contains a separate policy configuration; the repository also includes test suites.

## Explore

From the repository root, inspect the available options with:

```sh
python3 -m policy_guard.cli --help
```

To evaluate a command string without executing it:

```sh
python3 -m policy_guard.cli --json 'git status'
```

The CLI returns exit code `0` for an allowed decision and `1` for a denied decision. With no command, it displays help and returns `0`; a caller must not treat an empty invocation as approval of a command.

## Scope and limitations

This project is an experiment in policy checks, not a sandbox or proof that an allowed command is safe. Rules can miss harmful behavior or reject benign work. Effective enforcement depends on how the calling application uses the decision. Review the code and test the exact policy and environment before relying on it.

See the [tests](tests/) and [license](LICENSE).
