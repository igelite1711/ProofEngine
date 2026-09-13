// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! proof-cli: command-line front end over the library crates (Phase 7).
//! Adds no trust logic of its own: every artifact is re-verified on load,
//! every time input is an explicit flag, keys are supplied per invocation.

pub mod artifact;
pub mod check;
pub mod demo;
pub mod doctor;
pub mod graph;
pub mod ingest;
pub mod inspect;
pub mod journey;
pub mod make;
pub mod port;
pub mod store;

use std::collections::{HashMap, HashSet};

/// Exit codes: 0 PASS, 1 FAIL/INDETERMINATE verdict, 2 usage or engine error.
pub const EXIT_OK: i32 = 0;
pub const EXIT_FAIL: i32 = 1;
pub const EXIT_ERR: i32 = 2;

/// Version information for the CLI. The CLI version is derived from the
/// package version so the two can never drift apart.
pub const VERSION_INFO: &str = concat!(
    "Proof Engine CLI\n\nCLI       ",
    env!("CARGO_PKG_VERSION"),
    "\nProtocol  V1\nFormat    V1\nCrypto    Ed25519/P-256\nRepository https://github.com/igelite1711/ProofEngine",
);

/// Parsed command line: subcommand + positional args + `--flag value` flags.
/// Deliberately hand-rolled (no new dependencies in V0.1).
#[derive(Debug, Default)]
pub struct Cli {
    pub command: String,
    pub positional: Vec<String>,
    values: HashMap<String, String>,
    multi: HashMap<String, Vec<String>>,
    flags: HashSet<String>,
}

/// Short flag aliases (single-char flags map to long names).
fn short_flag_alias(name: &str) -> &str {
    match name {
        "o" => "out",
        "h" => "help",
        "q" => "quiet",
        "j" => "json",
        "p" => "proof",
        "c" => "clock",
        "k" => "skew",
        "s" => "subject",
        "t" => "type",
        _ => name,
    }
}

impl Cli {
    pub fn parse(args: &[String]) -> Result<Cli, String> {
        let mut it = args.iter().peekable();
        let raw = it
            .next()
            .ok_or_else(|| "missing command (try `help`)".to_string())?
            .clone();
        // Normalize GNU-style top-level flags: `proof-cli --help` / `-h` acts
        // like `help`, `--version` like `version`. Otherwise `--help` would be
        // consumed as an unknown command name (exit 2) instead of help.
        let command = match raw.as_str() {
            "--help" | "-h" => "help".to_string(),
            "--version" => "version".to_string(),
            _ => raw,
        };
        let mut cli = Cli {
            command,
            ..Cli::default()
        };
        while let Some(a) = it.next() {
            // Handle "-" as positional argument (for stdin support)
            if a == "-" {
                cli.positional.push(a.clone());
                continue;
            }
            // Handle short flags like `-o <value>`
            if let Some(name) = a
                .strip_prefix('-')
                .filter(|s| !s.starts_with('-') && s.len() == 1)
            {
                let long_name = short_flag_alias(name).to_string();
                match it.peek() {
                    Some(v) if !v.starts_with('-') => {
                        let value = it
                            .next()
                            .ok_or_else(|| "missing value for short flag".to_string())?
                            .clone();
                        cli.multi
                            .entry(long_name.clone())
                            .or_default()
                            .push(value.clone());
                        cli.values.insert(long_name, value);
                    }
                    _ => {
                        cli.flags.insert(long_name);
                    }
                }
                continue;
            }
            let Some(name) = a.strip_prefix("--") else {
                cli.positional.push(a.clone());
                continue;
            };
            let (name, inline) = match name.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (name.to_string(), None),
            };
            // A `--flag` with no inline value takes the next token as its
            // value only when that token does not look like another flag.
            // Peek first: a boolean flag must never swallow `--other` tokens.
            // Exception: "-" is always treated as a value (for stdin support).
            let value = match inline {
                Some(v) => v,
                None => match it.peek() {
                    Some(v)
                        if v.as_str() == "-" || (!v.starts_with("--") && !v.starts_with('-')) =>
                    {
                        it.next()
                            .ok_or_else(|| "missing value for flag".to_string())?
                            .clone()
                    }
                    _ => {
                        // Boolean flag (no value).
                        cli.flags.insert(name);
                        continue;
                    }
                },
            };
            cli.multi
                .entry(name.clone())
                .or_default()
                .push(value.clone());
            cli.values.insert(name, value);
        }
        Ok(cli)
    }
    /// Value of a required flag.
    pub fn req(&self, name: &str) -> Result<String, String> {
        self.values
            .get(name)
            .cloned()
            .ok_or_else(|| format!("missing required flag --{name}"))
    }

    /// Value of an optional flag.
    pub fn opt(&self, name: &str) -> Option<String> {
        self.values.get(name).cloned()
    }

    /// All values of a repeatable flag, in order.
    pub fn many(&self, name: &str) -> Vec<String> {
        self.multi.get(name).cloned().unwrap_or_default()
    }

    /// True when a boolean flag was present.
    pub fn has(&self, name: &str) -> bool {
        self.flags.contains(name)
    }

    /// True when --quiet is set (suppress progress output).
    pub fn quiet(&self) -> bool {
        self.has("quiet")
    }

    /// Proof path: `--proof <file>` or a single positional argument
    /// (`proof verify proof.json`, `-` for stdin). Additive alias — every
    /// existing `--proof` invocation behaves exactly as before.
    pub fn proof_path(&self) -> Result<String, String> {
        if let Some(p) = self.opt("proof") {
            return Ok(p);
        }
        match self.positional.as_slice() {
            [p] => Ok(p.clone()),
            [] => Err(
                "missing required flag --proof (or pass the proof path positionally, e.g. `verify proof.json`; `-` reads stdin)"
                    .to_string(),
            ),
            _ => Err("expected a single proof path (got several positional arguments)".to_string()),
        }
    }

    /// Required u64 flag.
    pub fn req_u64(&self, name: &str) -> Result<u64, String> {
        self.req(name)?
            .parse()
            .map_err(|_| format!("--{name} must be a u64"))
    }

    /// Optional u64 flag.
    pub fn opt_u64(&self, name: &str) -> Result<Option<u64>, String> {
        match self.opt(name) {
            None => Ok(None),
            Some(v) => v
                .parse()
                .map(Some)
                .map_err(|_| format!("--{name} must be a u64")),
        }
    }
}

/// Parse `k=v[,k=v…]` into flat metadata / claim fields. Values are text,
/// `true`/`false`, or unsigned integers (matching the closed MetaValue set).
///
/// Pairs are sorted into canonical CBOR map order (by encoded key bytes,
/// exactly as `proof_format::cbor::encode_canonical` orders map keys) before
/// return. The protocol's round-trip check compares decoded field order
/// against supplied order, so without this `--claim b=1,a=2` would fail with
/// a confusing SCHEMA_VIOLATION while `--claim a=2,b=1` succeeds. Sorting
/// here is presentation-layer canonicalization: previously-successful inputs
/// were already sorted, so their bytes are unchanged (no protocol change).
pub fn parse_fields(
    spec: Option<String>,
) -> Result<Vec<(String, proof_core::model::MetaValue)>, String> {
    let Some(spec) = spec else {
        return Ok(vec![]);
    };
    let mut out = vec![];
    for pair in spec.split(',') {
        let Some((k, v)) = pair.split_once('=') else {
            return Err(format!("bad field `{pair}` (expected k=v)"));
        };
        if k.is_empty() || v.is_empty() {
            return Err(format!("bad field `{pair}` (empty key or value)"));
        }
        let mv = if v == "true" {
            proof_core::model::MetaValue::Bool(true)
        } else if v == "false" {
            proof_core::model::MetaValue::Bool(false)
        } else if let Ok(n) = v.parse::<u64>() {
            proof_core::model::MetaValue::Uint(n)
        } else {
            proof_core::model::MetaValue::Text(v.to_string())
        };
        out.push((k.to_string(), mv));
    }
    // Canonicalize field order to match the encoder's map ordering.
    out.sort_by(|a, b| {
        let ka =
            proof_format::cbor::encode_canonical(&proof_format::cbor::CborValue::Text(a.0.clone()));
        let kb =
            proof_format::cbor::encode_canonical(&proof_format::cbor::CborValue::Text(b.0.clone()));
        ka.cmp(&kb)
    });
    Ok(out)
}

/// Load an Ed25519 key from `--seed`: `test` selects the fixed test key
/// (fixtures/demos ONLY); otherwise 64 hex chars = 32 seed bytes.
pub fn load_key(seed: &str) -> Result<proof_crypto::Ed25519Key, String> {
    load_key_material(seed, "--seed")
}

fn load_key_material(seed: &str, what: &str) -> Result<proof_crypto::Ed25519Key, String> {
    if seed == "test" {
        return Ok(proof_crypto::build::fixtures::test_key());
    }
    let bytes = hex::decode(seed).map_err(|e| format!("{what} bad hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{what} must be `test` or 64 hex chars (32 bytes)"))?;
    Ok(proof_crypto::Ed25519Key::from_seed(&arr))
}

/// Load a key for commands taking `--seed`/`--seed-file`. `--seed-file`
/// reads the seed from a file (capped by MAX_INPUT_FILE_BYTES) so raw key
/// material never lands in argv, shell history, or process listings;
/// `--seed` keeps working for demos/tests. The two flags must not combine.
pub fn load_key_opt(cli: &Cli) -> Result<proof_crypto::Ed25519Key, String> {
    match (cli.opt("seed"), cli.opt("seed-file")) {
        (Some(_), Some(_)) => Err("--seed and --seed-file are mutually exclusive".into()),
        (None, Some(path)) => {
            let seed = read_input_file(&path)?;
            load_key_material(seed.trim(), "--seed-file")
        }
        (Some(seed), None) => load_key(&seed),
        (None, None) => Err("missing required flag --seed (or --seed-file)".into()),
    }
}

pub fn limits() -> proof_core::Limits {
    proof_core::Limits::default()
}

/// Print progress to stderr unless --quiet is set.
pub fn progress(quiet: bool, msg: &str) {
    if !quiet {
        eprintln!("{msg}");
    }
}

/// Cap for any file the CLI reads (artifacts, proofs, policies). Well above
/// the largest legitimate input (1 MiB proof → ~2 MiB hex JSON): oversized
/// files are refused with a clean error instead of being buffered without
/// bound (Phase 7 hostile review H1).
pub const MAX_INPUT_FILE_BYTES: u64 = 8 << 20;

/// Read stdin fully, capped at [`MAX_INPUT_FILE_BYTES`].
pub fn read_stdin_text() -> Result<String, String> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::io::stdin()
        .by_ref()
        .take(MAX_INPUT_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read stdin: {e}"))?;
    if buf.len() as u64 > MAX_INPUT_FILE_BYTES {
        return Err("stdin: input too large".to_string());
    }
    String::from_utf8(buf).map_err(|_| "stdin: invalid UTF-8".to_string())
}

/// Read a CLI input: file at `path`, or stdin when `path` is `-`.
/// Returns the text plus a human label (`stdin` for pipes, else the path).
pub fn read_input_text(path: &str) -> Result<(String, String), String> {
    if path == "-" {
        Ok((read_stdin_text()?, "stdin".to_string()))
    } else {
        Ok((read_input_file(path)?, path.to_string()))
    }
}

/// Read a CLI input file with the size cap enforced during buffering (no
/// TOCTOU window: at most one byte over the cap is ever read).
// PE-SEC-002: 8 MiB cap enforced during buffering.
pub fn read_input_file(path: &str) -> Result<String, String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut buf = Vec::new();
    f.by_ref()
        .take(MAX_INPUT_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read {path}: {e}"))?;
    if buf.len() as u64 > MAX_INPUT_FILE_BYTES {
        return Err(format!(
            "{path}: file too large (>{MAX_INPUT_FILE_BYTES} bytes)"
        ));
    }
    String::from_utf8(buf).map_err(|_| format!("{path}: invalid UTF-8"))
}

/// All public commands with one-line summaries. Single source of truth for
/// help text and shell completion (never duplicate this list by hand).
pub const COMMANDS: &[(&str, &str)] = &[
    ("verify", "Verify a proof"),
    ("evaluate", "Verify a proof and evaluate a policy"),
    ("explain", "Explain a verification + policy result"),
    (
        "inspect",
        "Show proof contents (read-only, no trust decisions)",
    ),
    ("graph", "Visualize proof relationships"),
    ("create-event", "Create an event artifact"),
    ("attest", "Create a signed attestation"),
    ("add-evidence", "Add an evidence artifact"),
    ("relate", "Create a relationship edge"),
    ("build", "Assemble artifacts into a proof"),
    ("revoke", "Revoke an attestation"),
    ("supersede", "Supersede an attestation"),
    ("withdraw", "Withdraw reliance on an artifact"),
    ("compromise", "Mark an identity compromised from an instant"),
    ("export", "Export an artifact to the standard envelope"),
    ("import", "Import a standard envelope (validated)"),
    ("convert", "Normalize a legacy artifact file idempotently"),
    ("compose", "Compose proofs by union of members"),
    ("resolve", "Resolve transitive composition linkage"),
    ("batch-verify", "Verify many proofs under one context"),
    ("ingest", "Ingest JSONL event records into event artifacts"),
    ("demo", "Run the end-to-end demonstration"),
    ("doctor", "Diagnose the local environment"),
    ("version", "Show version information"),
    ("completion", "Print shell completion script"),
    ("help", "Show help"),
];

/// Per-command help. `help <command>` or `<command> --help` prints the topic.
pub fn command_help(cmd: &str) -> Option<&'static str> {
    Some(match cmd {
        "verify" => "\
verify — run the verification pipeline over a proof.

USAGE
  proof-cli verify --proof <file> --clock <u64> [options]
  proof-cli verify <file> --clock <u64>            (positional proof path)
  proof-cli verify --proof - --clock <u64>         (read proof from stdin)

OPTIONS
  --clock <u64>               verification timestamp (required; wall clock never read)
  --skew <u64=300>            clock skew leeway
  --revocations-known-at <u64> revocation freshness bound (omit → lifecycle UNKNOWN, fail closed)
  --status <file>             status object(s), repeatable
  --authority <keyref>        revocation authority key(s), repeatable
  --trusted <keyref>          trusted issuer(s) echoed in context, repeatable
  --esp256                    enable P-256/ES256 in addition to Ed25519 (default Ed25519-only)
  --historical                verify deprecated algs as was-valid-then (forensics; policy still decides current trust)
  --report-all                collect past CANONICAL diagnostics instead of fail-fast
  --accepted-vocab <ns:max>   accepted vocabulary namespace bound, repeatable + comma-separated (informational notes)
  --extra-grounded <TYPE>     extra trust-relevant edge kind(s), repeatable + comma-separated
  --require-acyclic           provenance DAG profile: reject any relationship cycle (opt-in; default allows REFERENCES cycles as linkage)
  --out, -o <file>            write JSON report to file (`-` = stdout); default prints JSON to stdout
  --quiet, -q                 suppress the human summary on stderr

OUTPUT
  stdout = machine-readable JSON report (never prose, never color).
  stderr = human summary (✓/✗ per stage, RESULT, exit meaning).
  exit 0 = valid, 1 = invalid verdict, 2 = usage/engine error.",
        "evaluate" => "\
evaluate — verify a proof and evaluate a declarative policy over the result.

USAGE
  proof-cli evaluate --proof <file> --policy <file> --clock <u64> [options]

OPTIONS
  --policy <file>             policy JSON (required)
  --clock <u64>               verifier clock (required)
  --trusted <keyref>          trusted issuer(s), repeatable
  --revoked <id[,id…]>        revoked id(s), repeatable
  --status <file>             signed status objects (repeatable)
  --authority <keyref>        revocation authority (repeatable)
  --revocations-known-at <u64> freshness bound (required for PASS)
  --skew <u64>                clock skew leeway (default 300)
  --esp256 --historical --report-all --accepted-vocab <ns:max> --extra-grounded <TYPE> --require-acyclic
                              verifier-policy flags (same semantics as verify)
  --json, -j                  print the merged policy_outcome + report JSON on stdout

  exit 0 = policy PASS, 1 = FAIL/INDETERMINATE, 2 = usage/engine error.",
        "explain" => "\
explain — verify + policy, then print a human-readable causal explanation.

USAGE
  proof-cli explain --proof <file> --policy <file> --clock <u64> [options]

Same required flags as evaluate (--clock, --revocations-known-at, --status,
--authority, --trusted, --skew). Differences: --json is ignored (prose only
on stdout; use --out <file> to also save the JSON report). Exit codes as evaluate.",
        "inspect" => "\
inspect — show what a proof or artifact contains. Performs NO trust decisions.

USAGE
  proof-cli inspect --proof <file>
  proof-cli inspect <file>
  proof-cli inspect <file> --json   (machine-readable contents on stdout)
  proof-cli inspect <artifact.json> (event/attestation/evidence/relationship/status)

INSPECTED is not VERIFIED. Use `verify` to check validity.",
        "graph" => "\
graph — visualize the relationships inside a proof.

USAGE
  proof-cli graph --proof <file> [--format text|dot|mermaid]

  text    terminal diagram (default)
  dot     Graphviz output (pipe to `dot -Tsvg > graph.svg`)
  mermaid `graph TD` diagram for Markdown/docs",
        "build" => "\
build — assemble artifact files into a canonical, id-bound proof.

USAGE
  proof-cli build --kind <t> --subject <s> --predicate <p> [--object <o>]
    [--at-time <u64>] [--context k=v,…] --created-at <u64>
    --events <f[,f…]> --attestations <f[,f…]>
    --evidence <f[,f…]> --relationships <f[,f…]> --out <file>

  Pass `--evidence \"\"` (and/or `--relationships \"\"`) for a proof with no
  members of that kind. --from/--to/--object take artifact ids
  (evt:/att:/evd:…), never bare labels like invoice:i9.",
        "create-event" => "\
create-event — write an event artifact (JSON wrapper around canonical CBOR).

USAGE
  proof-cli create-event --type <event.type> --subject <id>
    --effective-at <u64> --payload-hex <64|96 hex> [--meta k=v,…] --out <file>

  Field order in --meta is free: pairs are canonicalized automatically.",
        "attest" => "\
attest — bind an issuer (signing key) to a claim and sign it.

USAGE
  proof-cli attest --seed <test|64hex> --subject <id> --claim-type <t>
    [--claim k=v,…] --issued-at <u64> [--expires-at <u64>]
    [--evidence-ref <id>] --out <file>

  Prefer --seed-file <path> over --seed <hex> (argv is visible to ps/history).
  Field order in --claim is free: pairs are canonicalized automatically.",
        "add-evidence" => "\
add-evidence — write an evidence artifact (id-bound, no signature of its own).

USAGE
  proof-cli add-evidence --kind <kind> --digest-hex <64|96 hex>
    [--attestation-ref <id>] [--hint <text>] --out <file>",
        "relate" => "\
relate — write a relationship edge between two artifact ids.

USAGE
  proof-cli relate --from <artifact-id> --type <TYPE> --to <artifact-id>
    [--evidence-ref <id>] [--attestation-ref <id>] --out <file>

  --from/--to take evt:/att:/evd: ids, NOT bare labels (fails fast with a hint).
  Exception: EQUIVALENT endpoints may name external identity refs
  (e.g. did:org:acme) as asserted — grounding (--evidence-ref/--attestation-ref)
  is still required and shaped ids must still resolve.",
        "revoke" => "\
revoke — write a signed revocation status object for an attestation.

USAGE
  proof-cli revoke --seed <test|64hex> --target <id> [--reason <t>] --at <u64> --out <file>",
        "supersede" => "\
supersede — write a signed supersession status object.

USAGE
  proof-cli supersede --seed <test|64hex> --old <id> --new <id> --at <u64> --out <file>",
        "withdraw" => "\
withdraw — write a signed withdrawal (cease reliance; history preserved).

USAGE
  proof-cli withdraw --seed <test|64hex> --target <id> [--reason <t>] --at <u64> --out <file>",
        "compromise" => "\
compromise — write a signed compromise marking (taints at/after the instant).

USAGE
  proof-cli compromise --seed <test|64hex> --target <keyref|id> --compromised-at <u64> [--reason <t>] --at <u64> --out <file>",
        "export" => "\
export — wrap a CLI artifact as a standard ArtifactEnvelope (validated).

USAGE
  proof-cli export --proof <file> --out <envelope.json>",
        "import" => "\
import — validate an ArtifactEnvelope and write the CLI artifact shape.

USAGE
  proof-cli import --proof <envelope.json> --out <file>",
        "convert" => "\
convert — normalize a legacy artifact file idempotently.

USAGE
  proof-cli convert --proof <file> --out <file>",
        "compose" => "\
compose — union member sets from multiple proofs into one composite proof,
recording the sources as composition linkage (bound by the new proof_id).

USAGE
  proof-cli compose --proofs <a.json,b.json> --kind <k> --subject <s> --predicate <p> --created-at <u64> --out <proof.json>",
        "resolve" => "\
resolve — fetch-and-verify transitive composition linkage against a file
store (bundle layer; root validity unchanged, incompleteness is fail-closed).

USAGE
  proof-cli resolve --proof <file> --store <dir> --clock <u64> [--depth <u64>=8] [--status <f>] [--authority <k>] [--trusted <keyref>] [--revocations-known-at <u64>] [--esp256] [--historical] [--report-all] [--accepted-vocab <ns:max>] [--extra-grounded <TYPE>] [--require-acyclic] (incomplete linkage → exit 1)",
        "batch-verify" => "\
batch-verify — verify many proofs under one shared context. Each member
verifies independently with identical semantics to verify (no sampling,
no short-circuit); exit 0 iff every member is crypto- and evidence-Valid.

USAGE
  proof-cli batch-verify --proofs <a.json,b.json> --clock <u64> [--max-batch <u64>=256] [--status <f>] [--authority <k>] [--trusted <keyref>] [--revocations-known-at <u64>] [--esp256] [--historical] [--report-all] [--accepted-vocab <ns:max>] [--extra-grounded <TYPE>] [--require-acyclic] [--out <file>]",
        "ingest" => "\
ingest — read newline-delimited external event records (file or stdin) and
write canonical event artifacts plus a manifest. Fail-closed: the first
malformed line aborts unless --skip-bad lists skips in the manifest instead.

USAGE
  proof-cli ingest [--in <records.jsonl>=stdin] --out-dir <dir> [--out <manifest.json>] [--skip-bad] [--dry-run]
  manifest: {ingested, ids, skipped, dry_run}. Exit 0 clean, 1 partial (--skip-bad with skips), 2 usage/engine error.",
        "demo" => "\
demo — deterministic end-to-end story: build → verify PASS → tamper → FAIL →
revoke → FAIL. Uses the core only; no simulated results.

USAGE
  proof-cli demo [--out <dir>=demo/out]
  proof-cli demo --interactive   (guided 60-second tour; needs a terminal)",
        "doctor" => "\
doctor — check the local environment (versions, limits, fixtures, examples).

USAGE
  proof-cli doctor

Exit 0 all checks pass, 1 any check fails. Distinguishes `environment healthy` from `proof verified`.",
        "version" => "\
version — show CLI / protocol / format versions for reproducibility.

USAGE
  proof-cli version",
        "completion" => "\
completion — print a shell completion script generated from the command table.

USAGE
  proof-cli completion bash|zsh|fish|powershell

Install: `proof-cli completion bash >> ~/.bash_completion` (or the
equivalent for your shell).",
        "help" => "\
help — show help for a command.

USAGE
  proof-cli help [command]
  proof-cli <command> --help",
        _ => return None,
    })
}

/// Generate a shell completion script from [`COMMANDS`].
pub fn completion_script(shell: &str) -> Result<String, String> {
    let names: Vec<&str> = COMMANDS.iter().map(|(n, _)| *n).collect();
    match shell {
        "bash" => Ok(format!(
            "# proof-cli bash completion (generated; do not hand-edit)\n\
             _proof_cli_complete() {{\n\
             \x20   local cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n\
             \x20   if [ \"$COMP_CWORD\" -eq 1 ]; then\n\
             \x20       COMPREPLY=($(compgen -W \"{}\" -- \"$cur\"))\n\
             \x20   else\n\
             \x20       COMPREPLY=($(compgen -W \"--proof --policy --clock --skew --out --quiet --json --trusted --authority --status --seed --seed-file --format --esp256 --historical --report-all --accepted-vocab --extra-grounded\" -- \"$cur\"))\n\
             \x20   fi\n\
             }}\n\
             complete -F _proof_cli_complete proof-cli\n",
            names.join(" ")
        )),
        "zsh" => Ok(format!(
            "#compdef proof-cli\n\
             # proof-cli zsh completion (generated; do not hand-edit)\n\
             _proof_cli() {{\n\
             \x20   local -a cmds\n\
             \x20   cmds=({})\n\
             \x20   _arguments '1:command:->cmd' '*: :->args'\n\
             \x20   case $state in\n\
             \x20   cmd) _describe 'command' cmds ;;\n\
             \x20   *) _files ;;\n\
             \x20   esac\n\
             }}\n\
             _proof_cli\n",
            names
                .iter()
                .zip(COMMANDS.iter().map(|(_, d)| *d))
                .map(|(n, d)| format!("'{n}:{d}'"))
                .collect::<Vec<_>>()
                .join(" ")
        )),
        "fish" => Ok(names
            .iter()
            .zip(COMMANDS.iter().map(|(_, d)| *d))
            .map(|(n, d)| format!("complete -c proof-cli -f -n '__fish_use_subcommand' -a {n} -d '{d}'"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"),
        "powershell" => Ok(format!(
            "# proof-cli PowerShell completion (generated; do not hand-edit)\n\
             Register-ArgumentCompleter -Native -CommandName proof-cli -ScriptBlock {{\n\
             \x20   param($wordToComplete, $commandAst, $cursorPosition)\n\
             \x20   @({}) | Where-Object {{ $_ -like \"$wordToComplete*\" }} |\n\
             \x20       ForEach-Object {{ [CompletionResult]::new($_, $_, 'ParameterValue', $_) }}\n\
             }}\n",
            names
                .iter()
                .map(|n| format!("'{n}'"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        other => Err(format!(
            "unknown shell `{other}` (expected bash|zsh|fish|powershell)"
        )),
    }
}

/// Strip terminal escape sequences and control characters from untrusted
/// strings (ids, labels, metadata, error context) before printing. Prevents
/// terminal-escape injection from malicious proofs.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Swallow the escape sequence: CSI (`[` + params + final byte),
            // or a single following char for non-CSI escapes.
            if chars.peek() == Some(&'[') {
                chars.next();
                for c2 in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&c2) {
                        break;
                    }
                }
            } else {
                chars.next();
            }
            continue;
        }
        if c.is_control() && c != '\n' && c != '\t' {
            continue;
        }
        out.push(c);
    }
    out
}

/// Color enabled only as progressive enhancement: stderr must be a terminal,
/// `NO_COLOR` must be unset, and `TERM` must not be `dumb`. Never used for
/// machine-readable stdout (JSON stays pure).
pub fn use_color() -> bool {
    use std::io::IsTerminal;
    std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true)
        && std::io::stderr().is_terminal()
}

fn paint(code: &str, s: &str) -> String {
    if use_color() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// Green text when color is enabled, plain otherwise.
pub fn green(s: &str) -> String {
    paint("32", s)
}

/// Red text when color is enabled, plain otherwise.
pub fn red(s: &str) -> String {
    paint("31", s)
}

/// Bold text when color is enabled, plain otherwise.
pub fn bold(s: &str) -> String {
    paint("1", s)
}

pub const USAGE: &str = "\
proof-cli — Proof Engine command line (V1.1)

Exit codes: 0 = PASS/valid, 1 = FAIL/INDETERMINATE verdict, 2 = usage or engine error.
All commands accept --quiet to suppress progress output on stderr.
Use -o <file> as shorthand for --out <file>.

CORE
  verify       Verify a proof
  evaluate     Verify a proof and evaluate a policy
  explain      Explain a verification result (requires --policy)
  inspect      Inspect a proof (read-only, no trust decisions)
  graph        Visualize proof relationships

CREATION
  create-event Create an event artifact
  attest       Create a signed attestation
  add-evidence Add an evidence artifact
  relate       Create a relationship edge
  build        Assemble artifacts into a proof

LIFECYCLE
  revoke       Revoke an attestation
  supersede    Supersede an attestation
  withdraw     Withdraw evidence (signed)
  compromise   Mark an issuer compromised (signed)

PORTABILITY
  export       Export artifacts as envelopes
  import       Import artifacts from envelopes
  convert      Convert artifact formats
  compose      Compose proofs with linkage
  resolve      Resolve transitive linkage
  batch-verify Verify many proofs at once
  ingest       Ingest JSONL event records

DEVELOPMENT
  demo         Run the end-to-end demonstration (--interactive for the tour)
  doctor       Diagnose the local environment
  version      Show version information
  completion   Print shell completion (bash|zsh|fish|powershell)
  help         Show this text (or `help <command>` for details)

COMMON FLAGS
  --quiet, -q  Suppress progress output on stderr
  --json, -j   Machine-readable JSON output (verify, evaluate)
  --out, -o    Output file (`-` = stdout)
  --clock      Verification timestamp (u64, mandatory for verify/evaluate)
  --skew       Clock skew leeway (u64, default 300)

The proof path may be positional: `verify proof.json` means
`verify --proof proof.json`. `-` reads the proof from stdin.

EXAMPLES
  proof-cli demo
  proof-cli verify proof.json --clock 1700000300
  proof-cli inspect proof.json
  proof-cli graph proof.json --format dot
  proof-cli help verify

Artifacts are JSON wrappers around canonical CBOR bytes (hex); bytes are
re-verified on every load — ids recomputed, signatures checked. Seeds are for
demos/tests only; production key handling is out of scope for V1.0.
Prefer --seed-file <path> over --seed <hex>: raw key material in argv is
visible to ps(1) and shell history; the two flags never combine.";
