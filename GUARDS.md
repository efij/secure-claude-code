# Guard Registry

Runwall is organized like a local YARA-style signature engine:

- one guard pack equals one focused signature set
- profiles enable groups of packs without changing code
- plain-text regex and config files keep tuning simple
- families keep the registry readable without changing enforcement behavior
- hooks stay small and composable instead of becoming one giant script

For the plain-English deep dive on every implemented signature, see [SIGNATURES.md](SIGNATURES.md).

## Built-In Runtime Guards

These protections are implemented directly in the Tool Trust Plane instead of as standalone hook modules:

- `command-shadowing-guard`: blocks trusted command names that resolve to unreviewed local paths instead of reviewed system or package-managed tools
- `unknown-executable-guard`: prompts on first-seen PATH tools from unreviewed local origins
- `temp-download-exec-guard`: blocks execution from temp, cache, and download locations
- `tool-drift-guard`: prompts when a previously trusted tool changes path, hash, or execution shape
- `interpreter-wrapper-guard`: blocks trusted tools that suddenly resolve through inline interpreters or wrapper chains
- `path-prepend-hijack-guard`: blocks trusted commands when PATH order causes a local interceptor to win over a reviewed system or package-managed binary
- `shell-alias-hijack-guard`: blocks alias and function overrides for trusted tool names inside shell command payloads
- `package-runner-wrapper-guard`: prompts when one-shot package runners execute mutable or remote tool sources
- `generated-tool-chain-guard`: prompts when a newly created local executable is run before it has been reviewed
- `symlink-tool-swap-guard`: blocks trusted or approved local tools that suddenly resolve through a symlinked swap target

## Built-In Hook Trust Guards

These protections are implemented directly in the Hook Trust Plane instead of as standalone hook modules:

- `hook-review-boundary-guard`: prompts on first-seen git hooks, package install scripts, and plugin hook surfaces before they become trusted recurring execution paths
- `hook-drift-guard`: prompts when a previously observed or approved hook-bearing surface changes its body
- `hook-origin-guard`: blocks hook bodies that jump to temp, download, cache, or remote execution sources
- `hook-secret-access-guard`: blocks hook-bearing surfaces that read local secret files, cloud credentials, SSH material, or agent auth state
- `hook-policy-tamper-guard`: blocks hook-bearing surfaces that target Runwall, MCP, plugin, or instruction control files
- `hook-archive-exfil-guard`: blocks hook-bearing surfaces that compress local data and immediately upload or transfer it
- `hook-prod-breakglass-guard`: blocks hook-bearing surfaces that hide production shells, dumps, port-forwards, or destructive infra actions
- `hook-review-bypass-guard`: blocks hook-bearing surfaces that carry `--no-verify`, hook-disabling flags, or review-bypass language
- `hook-wrapper-escalation-guard`: blocks inline shell or interpreter wrapper execution inside hook-bearing surfaces
- `hook-fanout-network-guard`: blocks hook-bearing surfaces that add outbound fetch, upload, webhook, or tunnel behavior
- `hook-stealth-persistence-guard`: blocks stealthy background, delayed, or redirection-heavy persistence behavior hidden in hooks

## Built-In Flow, Approval, Service, Browser, and Agent Guards

These protections are implemented directly in native Runwall trust planes instead of standalone hook modules:

- `sensitive-data-flow-guard`: blocks outbound transfers and publishes after the same session already touched sensitive data
- `public-exposure-surface-guard`: blocks direct or session-derived sensitive data from being sent to public or externally shared surfaces such as gists, public repos, public channels, and public object storage
- `broad-exposure-surface-guard`: prompts before sending potentially sensitive material to broad collaboration surfaces such as repo comments or chat channels when private visibility is not confirmed
- `public-exposure-precursor-guard`: blocks sensitive sessions from widening exposure through precursor actions such as public repo flips, public share-link creation, external webhook setup, and public object-store ACL changes
- `access-widening-precursor-guard`: prompts before access-widening precursor actions in `strict`, while `balanced` only prompts on the clearest public or external share and ACL expansion cases
- `public-retention-export-guard`: blocks durable export or replication of sensitive material into public or externally shared retention targets
- `retention-replication-guard`: prompts in `strict` before durable external backup, indexing, transcript persistence, or replication after a session already touched sensitive data
- `delayed-exfil-chain-guard`: blocks scheduled or backgrounded outbound exfil chains in `strict` when persistence is used to stage later upload, publish, or delivery behavior
- `public-artifact-flow-guard`: blocks writes into public artifacts, build outputs, and release bundles after a session already touched sensitive or production data
- `cross-agent-secret-flow-guard`: blocks one agent from exporting data that another agent in the same session already read from sensitive sources
- `clipboard-secret-flow-guard`: blocks clipboard bridges after the same session already touched sensitive or browser-exported data
- `secret-archive-prep-guard`: blocks archive or encoding prep after a session already touched sensitive data
- `browser-session-upload-guard`: blocks outbound transfers after a session already touched a sensitive authenticated browser session
- `cross-agent-browser-export-guard`: blocks one agent from uploading browser-captured output that another agent collected in the same session
- `local-admin-socket-guard`: blocks direct access to Docker, container runtime, DBus, SSH agent, and similar high-trust local sockets
- `sensitive-local-service-guard`: prompts before first use of sensitive localhost or private-service targets such as browser debug ports and local admin APIs
- `service-drift-guard`: prompts when a previously seen local service changes identity unexpectedly
- `metadata-endpoint-service-guard`: blocks access to cloud and platform metadata endpoints even when they do not look like normal public egress
- `local-kube-admin-guard`: blocks direct access to local or private Kubernetes control-plane endpoints
- `database-admin-service-guard`: prompts before first use of local database and admin-service ports that often bypass normal API review
- `browser-sensitive-domain-guard`: prompts before browser automation drives sensitive authenticated domains
- `browser-sensitive-export-guard`: blocks browser automation exports, captures, and downloads against sensitive authenticated domains
- `browser-session-cookie-guard`: blocks browser automation that exports cookies, storage state, local storage, or session storage from sensitive domains
- `browser-bulk-capture-guard`: blocks bulk DOM and full-page capture against sensitive authenticated domains
- `browser-download-dropper-guard`: blocks browser automation that downloads executable or archive payloads from sensitive domains
- `isolated-agent-guard`: blocks actions from agents that were explicitly isolated for review
- `isolated-parent-bridge-guard`: blocks child or delegated agents from executing around an isolated parent boundary
- `agent-fanout-guard`: prompts when many agents fan out inside one session before an outbound action

## Built-In Handoff and Delegated-Auth Guards

These protections are implemented directly in native Runwall trust planes instead of standalone hook modules:

- `token-handoff-guard`: blocks one actor from reusing delegated-auth flows that another actor already initiated in the same session
- `browser-session-handoff-guard`: blocks export or mutation after another actor already touched a sensitive authenticated browser surface
- `child-agent-secret-bridge-guard`: blocks cross-actor export after another actor already touched secret-bearing material
- `cross-runtime-session-bridge-guard`: prompts when a risky action crosses from one runtime into another inside the same session
- `artifact-to-subagent-guard`: prompts when one actor prepares artifact material and another actor later tries to export it
- `credential-file-handoff-guard`: blocks auth-broker or upload behavior after another actor already handled credential-bearing local files
- `session-reuse-drift-guard`: prompts when a risky action happens in a session that already spans too many actors and runtimes
- `delegation-overreach-guard`: prompts when a delegated child actor attempts a high-risk mutation or delegated-auth step
- `handoff-exfil-chain-guard`: blocks export once sensitive session power has already been accumulated in another actor context
- `broker-to-export-bridge-guard`: blocks delegated-auth material from being bridged into outbound export or publish channels
- `refresh-token-exchange-guard`: blocks refresh-token and token-exchange flows that would mint fresh delegated sessions
- `delegated-session-relay-guard`: blocks cookies, sessions, and tokens from being relayed into files, clipboard bridges, or outbound channels
- `broker-export-guard`: blocks direct export of live tokens or delegated credentials from auth brokers
- `broker-scope-escalation-guard`: prompts on elevated auth scopes, admin roles, and production-targeted delegated access
- `cloud-impersonation-broker-guard`: prompts on impersonation, role-assumption, and service-principal auth minting
- `sts-mint-guard`: prompts when STS-style or short-lived delegated cloud credentials are minted
- `device-flow-broker-guard`: prompts on device-code and browser-mediated delegated login flows
- `sso-helper-mint-guard`: prompts on SSO helper and interactive login flows that mint delegated user sessions
- `credential-helper-mint-guard`: prompts on helper commands that print or mint active tokens and login material
- `broker-drift-guard`: prompts when a previously observed delegated-auth broker changes executable identity underneath the same provider and class

## Built-In Memory, Knowledge, and App Guards

These protections are implemented directly in native Runwall trust planes instead of standalone hook modules:

- `memory-source-review-guard`: prompts before a new persistent memory surface becomes trusted
- `memory-drift-guard`: prompts when a trusted memory source changes
- `memory-remote-ingest-guard`: blocks remote or pasted external content from being written directly into persistent memory
- `memory-prompt-smuggling-guard`: blocks override or system-priority prompt language in memory
- `memory-policy-override-guard`: blocks memory content that tells the runtime to ignore Runwall or local policy
- `memory-secret-harvest-instruction-guard`: blocks memory instructions that tell the runtime to collect local or cloud secrets
- `memory-exfil-instruction-guard`: blocks memory instructions that stage upload, webhook, or publish behavior
- `memory-hidden-encoding-guard`: blocks encoded or hidden instruction bodies in memory surfaces
- `memory-tool-trust-override-guard`: blocks memory that silently widens tool or plugin trust boundaries
- `memory-quarantine-bypass-guard`: blocks reads or edits of memory sources that were explicitly quarantined
- `knowledge-source-review-guard`: prompts before a new vault, Obsidian, RAG, or mirrored knowledge surface becomes trusted
- `knowledge-drift-guard`: prompts when a trusted knowledge source changes
- `knowledge-remote-ingest-guard`: blocks remote or pasted external content from being written directly into trusted knowledge sources
- `knowledge-prompt-smuggling-guard`: blocks override and instruction-smuggling content inside vaults and RAG sources
- `knowledge-policy-override-guard`: blocks knowledge sources that attempt to weaken Runwall or local policy
- `knowledge-secret-harvest-instruction-guard`: blocks knowledge sources that instruct the runtime to collect secrets
- `knowledge-exfil-instruction-guard`: blocks knowledge sources that instruct outbound upload or publish behavior
- `knowledge-hidden-encoding-guard`: blocks encoded or hidden instruction bodies in trusted knowledge
- `knowledge-rag-cache-dropper-guard`: blocks staged shell, interpreter, or fetch-exec payloads in RAG and imported knowledge caches
- `knowledge-tool-install-bridge-guard`: blocks knowledge sources that try to bridge directly into tool, plugin, or MCP trust
- `knowledge-quarantine-bypass-guard`: blocks reads or edits of quarantined knowledge sources
- `app-token-mint-guard`: prompts on token or credential minting against authenticated control-plane apps
- `app-secret-admin-guard`: prompts on secret and environment administration against sensitive apps
- `app-role-grant-guard`: prompts on collaborator, role, and IAM-style grants
- `app-prod-deploy-guard`: prompts on production deployments and promotions through control-plane apps
- `app-bulk-export-guard`: prompts on bulk export from control-plane apps
- `app-protection-disable-guard`: blocks disabling branch protection, audit, rulesets, or similar safety controls
- `app-destroy-action-guard`: blocks destructive delete and teardown actions in control-plane apps
- `app-webhook-admin-guard`: prompts on webhook creation or mutation
- `app-member-invite-guard`: prompts on membership and collaborator invites
- `app-admin-browser-mutation-guard`: prompts when browser automation tries to perform high-risk admin mutations on sensitive domains

## Built-In Approval Integrity Guards

These protections are implemented directly in the Approval Integrity Plane instead of standalone hook modules:

- `approval-broad-scope-guard`: prompts when a wildcard or overly broad approval would otherwise silently match a high-risk action
- `approval-expiry-guard`: prompts when a previously valid approval has expired and should not be reused
- `approval-runtime-mismatch-guard`: prompts when an approval was issued for a different runtime adapter
- `approval-repo-mismatch-guard`: prompts when an approval from another workspace or repo is being reused
- `approval-parent-child-mismatch-guard`: prompts when an approval from one agent or subagent is being reused by another
- `approval-scope-mismatch-guard`: prompts when a similar approval exists, but for a different value or destination
- `approval-drift-invalidation-guard`: prompts when the reviewed approval fingerprint no longer matches the current request
- `approval-destination-drift-guard`: prompts when a reviewed local service or destination changed underneath the same approval
- `approval-tool-identity-drift-guard`: prompts when a reviewed tool approval no longer matches the current tool identity
- `approval-replay-guard`: blocks attempts to reuse a consumed one-shot approval
- `approval-unbounded-lifetime-guard`: surfaces risky approvals that have no expiry and no one-shot boundary in approval inventory views

## Built-In Safety-Control Guards

These protections are implemented directly in the Safety-Control Trust Plane instead of standalone hook modules:

- `audit-disable-guard`: blocks disabling audit, logging, or cloud-trail style evidence collection
- `backup-disable-guard`: blocks disabling backups, deleting snapshots, or setting retention to zero
- `rollback-tamper-guard`: blocks edits and commands that neuter rollback or restore paths
- `monitoring-disable-guard`: blocks disabling monitoring, telemetry, or alerting surfaces
- `alert-sink-rewire-guard`: prompts before rewiring alert or escalation destinations
- `runwall-state-wipe-guard`: blocks deletion or truncation of Runwall audit and state files
- `forensics-bundle-delete-guard`: blocks deletion of incident, evidence, provenance, SARIF, or forensics artifacts
- `incident-runbook-automation-tamper-guard`: prompts when incident-response or escalation guidance is weakened
- `release-safety-check-disable-guard`: blocks disabling SBOM, provenance, attestation, signing, or release verification steps
- `recovery-script-destroy-guard`: blocks deletion, truncation, or de-executable changes against backup, restore, rollback, and recovery scripts

## Built-In Fileless and Promotion Guards

These protections are implemented directly in native Runwall trust planes instead of standalone hook modules:

- `inline-fetch-exec-guard`: blocks remote fetch-and-execute chains hidden inside inline shell or interpreter execution
- `inline-encoded-loader-guard`: blocks encoded loader and decode-and-run behavior inside inline shells, Python, Node, and PowerShell
- `inline-process-substitution-guard`: blocks process-substitution chains that source or execute fetched content
- `inline-heredoc-dropper-guard`: blocks heredoc execution that stages loaders, exfiltration, or persistence
- `inline-eval-secret-guard`: blocks inline `eval` and `source` chains that combine secret access with loaders or outbound behavior
- `inline-env-payload-guard`: blocks inline execution driven by hidden environment payload variables
- `inline-python-loader-guard`: blocks risky `python -c` loader behavior with fetch, exec, secret, or outbound primitives
- `inline-node-loader-guard`: blocks risky `node -e` loader behavior with fetch, exec, secret, or outbound primitives
- `inline-shell-persistence-guard`: blocks inline execution that edits login, scheduler, or persistence surfaces
- `inline-policy-bypass-guard`: blocks inline execution that tries to disable Runwall or step around local review boundaries

## Built-In Release and Destructive-Intent Guards

These protections are implemented directly in native Runwall trust planes instead of standalone hook modules:

- `unexpected-publish-target-guard`: prompts before a publish or release path points at an unreviewed registry, raw host, or artifact target
- `prod-promote-guard`: prompts before package or release flows promote directly into production-like channels
- `registry-publish-drift-guard`: prompts when a previously reviewed release edge drifts to a new registry or target
- `release-manifest-target-guard`: prompts when package manifests, workflows, or release configs are retargeted to unreviewed destinations
- `image-push-prod-guard`: prompts before container images are pushed to production-like registries or channels
- `package-publish-prod-guard`: prompts before package publish flows cross the local review boundary
- `binary-release-upload-guard`: prompts before binary assets are uploaded into release edges
- `release-secret-bundle-guard`: blocks release and publish flows that appear to bundle secrets, keys, or credentials
- `release-signing-bypass-guard`: blocks release flows that disable signing, provenance, SBOM, or attestation behavior
- `release-channel-swap-guard`: prompts before release channels, repositories, or registries are rewritten to new destinations
- `mass-delete-intent-guard`: blocks obvious high-blast-radius recursive delete behavior
- `move-away-destruction-guard`: blocks moving critical trust files into backup, trash, temp, or disable-style destinations
- `truncate-clear-guard`: blocks or prompts on truncate, empty-write, clear-content, and zero-fill destructive paths
- `permission-lockout-guard`: blocks or prompts on deny-all chmod, ACL lockout, or immutable-flag destructive access changes
- `env-destroy-guard`: prompts before environment-bound secret or config destruction paths
- `secret-revoke-all-guard`: prompts before bulk token, secret, or credential revocation paths
- `role-remove-admin-guard`: prompts before destructive admin or role-removal actions
- `infra-teardown-guard`: blocks infrastructure teardown commands such as `terraform destroy`, `pulumi destroy`, or production namespace deletion
- `repo-wipe-guard`: blocks repository wipe, delete, or history-destruction paths
- `artifact-wipe-guard`: blocks destructive wiping of release or build artifacts
- `state-destroy-guard`: blocks destructive mutation or deletion of infrastructure state
- `bulk-disable-guard`: prompts before fan-out loops apply destructive disable or delete behavior broadly
- `blast-radius-delete-guard`: prompts before destructive actions widen scope with `--all`, recursive, or blast-radius style flags
- `database-destroy-guard`: blocks destructive database reset, drop, truncate, and flush behavior in strict mode
- `database-bulk-delete-guard`: prompts before broad database delete flows with no obvious scope narrowing in strict mode
- `cloud-resource-destroy-guard`: blocks destructive bucket, volume, queue, stream, topic, and snapshot removal in strict mode
- `key-destroy-guard`: prompts before destructive encryption, signing, and recovery key lifecycle actions in strict mode
- `ransomware-intent-guard`: prompts before encrypt-in-place or rekey behavior targets critical local trust files in strict mode
- `indirection-swap-guard`: blocks symlink, junction, bind-style, and other indirection swaps against critical surfaces in strict mode
- `delayed-destruction-guard`: prompts on delayed destructive automation and destructive scheduled writes in strict mode
- `resource-exhaustion-destroy-guard`: prompts on disk-fill, zero-fill, and fork-bomb style destructive setup in strict mode
- `file-nulling-guard`: blocks or prompts on emptying meaningful tracked text files, especially critical trust surfaces
- `file-stub-replacement-guard`: blocks or prompts on placeholder, no-op, or stub replacement of meaningful tracked files
- `file-junk-overwrite-guard`: blocks or prompts on ciphertext-like or opaque junk overwrites of meaningful tracked text files
- `foreign-header-overwrite-guard`: blocks or prompts on replacing text/config files with archive, HTML, PDF, or key-material style headers
- `split-step-destruction-guard`: prompts when the same session accumulates multiple destructive file-edit signals against one path in strict mode
- `remote-to-memory-promotion-guard`: blocks remote content promotion into persistent memory surfaces
- `remote-to-knowledge-promotion-guard`: blocks remote content promotion into knowledge, vault, and RAG surfaces
- `remote-to-hook-promotion-guard`: blocks remote content promotion into hook-bearing surfaces
- `remote-to-policy-promotion-guard`: blocks remote content promotion into policy, settings, and plugin control surfaces
- `remote-to-script-promotion-guard`: blocks remote content promotion into scripts, workflow files, and executable bins
- `remote-to-agent-doc-promotion-guard`: blocks remote content promotion into `CLAUDE.md`, `AGENTS.md`, and similar agent instruction files
- `raw-host-promotion-guard`: blocks promotion of content from raw file hosts and paste sites into trusted local authority surfaces
- `paste-to-trusted-surface-guard`: prompts before pasted external content is promoted into a trusted surface
- `promotion-quarantine-bypass-guard`: blocks reads or writes against promoted sources that were explicitly quarantined

## Built-In Review and Artifact Guards

These protections are implemented directly in native Runwall trust planes instead of standalone hook modules:

- `review-surface-review-guard`: prompts before a new PR, changelog, task-signoff, or incident-review surface becomes trusted
- `review-surface-drift-guard`: prompts when a previously trusted human review surface changes
- `review-quarantine-bypass-guard`: blocks access to a quarantined human review surface
- `pr-description-bypass-guard`: blocks merge-or-approve language that tries to bypass normal review in PR-facing surfaces
- `issue-comment-approval-launder-guard`: blocks issue or task text that claims to stand in for formal approval
- `release-notes-mislead-guard`: blocks "verified" or "fully reviewed" claims paired with raw or mutable external references
- `changelog-coverup-guard`: blocks language that hides, buries, or renames material changes in changelogs and release-facing notes
- `task-doc-secret-normalize-guard`: blocks real secret material disguised as a harmless sample or placeholder inside review-facing docs
- `incident-note-bypass-guard`: blocks incident or postmortem surfaces that try to skip escalation, paging, or post-incident review
- `review-template-tamper-guard`: prompts when PR or signoff templates remove required checklist or reviewer structure
- `approval-text-smuggling-guard`: blocks approval-token or signoff-smuggling text inside human review surfaces
- `human-review-override-guard`: blocks language telling humans to override local policy or ignore Runwall outcomes
- `review-surface-rewrite-guard`: blocks rewrites that redirect reviewers to raw, pasted, or mutable external approval links
- `artifact-source-review-guard`: prompts before a new generated report or evidence bundle becomes trusted
- `artifact-drift-guard`: prompts when a previously trusted artifact or report changes
- `artifact-quarantine-bypass-guard`: blocks access to a quarantined artifact or report surface
- `sarif-finding-suppression-guard`: blocks SARIF suppression markers, silent passes, and finding-hiding drift
- `sbom-source-swap-guard`: prompts when SBOM materials or external references drift to raw or mutable sources
- `provenance-mismatch-guard`: blocks weak or placeholder provenance, builder, and digest metadata
- `audit-report-secret-redaction-bypass-guard`: blocks live secrets from landing inside trusted reports or bundles
- `incident-bundle-poison-guard`: blocks incident bundles that weaken evidence handling or redirect operators to mutable external content
- `summary-falsification-guard`: blocks "all clear" summaries that still reference critical or failing conditions
- `checksum-report-drift-guard`: prompts when checksum fields look placeholder-like or inconsistent with a regenerated report
- `security-report-coverup-guard`: blocks language that suppresses or hides findings inside a trusted report
- `artifact-regeneration-mismatch-guard`: prompts when a generated artifact claims unknown, manual, or non-reviewable provenance
- `evidence-pointer-rewrite-guard`: blocks evidence pointers rewritten to raw, temp, or mutable external locations

## Built-In Data Store and IPC Guards

These protections are implemented directly in native Runwall trust planes instead of standalone hook modules:

- `sqlite-dump-guard`: blocks full SQLite dumps from local database files
- `sqlite-session-export-guard`: blocks copy or archive of session-bearing SQLite stores such as cookies, login data, and local auth state
- `redis-admin-export-guard`: blocks Redis export, save, and bulk-key enumeration flows against local instances
- `postgres-local-dump-guard`: prompts before local PostgreSQL dump and bulk-export behavior
- `browser-indexeddb-export-guard`: blocks export of browser IndexedDB, LevelDB, and similar storage roots
- `vector-store-export-guard`: prompts before copying or archiving local vector stores and embedding indexes
- `app-cache-db-copy-guard`: prompts before copying application cache databases and app-state stores
- `datastore-admin-shell-guard`: prompts before opening or driving local SQLite, PostgreSQL, or Redis admin surfaces
- `datastore-bulk-read-guard`: prompts before broad `SELECT *`, `COPY`, schema, and bulk-read datastore access
- `datastore-drift-guard`: prompts when an approved datastore target changes underneath its local trust record
- `credential-helper-ipc-guard`: blocks direct access to SSH agent, keyring, gpg-agent, and similar credential-helper IPC paths
- `named-pipe-admin-guard`: blocks named-pipe control paths that behave like privileged local admin channels
- `local-llm-socket-guard`: prompts before trusting local LLM endpoints and model-helper sockets
- `debug-helper-ipc-guard`: prompts before trusting local debug-helper targets
- `ide-backend-ipc-guard`: prompts before trusting IDE backend and extension-host IPC paths
- `agent-sidecar-ipc-guard`: prompts before trusting agent sidecar IPC paths
- `ipc-first-seen-review-guard`: prompts before a new local IPC helper becomes trusted
- `unix-socket-drift-guard`: prompts when an approved IPC target changes underneath its trust record
- `ipc-wrapper-bridge-guard`: blocks wrapper and inline-interpreter bridges against helper sockets and pipes
- `ipc-export-bridge-guard`: blocks upload and export bridges built directly on IPC helper channels

## Implemented Guards

### Secrets & Identity

Guards that keep tokens, sessions, credential stores, and delegated identity flows from quietly widening access or leaking off the box.

- `agent-session-secret-guard`: Blocks reads and exports of local auth, token, and session stores used by coding agents.
- `browser-cookie-guard`: Blocks reads and exports of browser cookie, login, and session stores.
- `browser-profile-export-guard`: Blocks copying or archiving full browser profiles that can contain sessions and saved credentials.
- `browser-remote-debug-guard`: Blocks browser remote-debugging launches that expose live sessions and cookies to the runtime.
- `clipboard-exfiltration-guard`: Blocks copying likely secrets and tokens into clipboard tools.
- `cloud-credential-assume-guard`: Prompts when agents try to assume cloud roles or impersonate service accounts for fresh runtime credentials.
- `cloud-key-creation-guard`: Blocks agent-driven creation of long-lived cloud access keys and service-account credentials.
- `config-secret-inline-guard`: Blocks live tokens and private keys from being inlined into workflow, deployment, and application config files.
- `credential-export-guard`: Blocks commands that export live credential material into files, clipboard channels, or outbound transfers.
- `desktop-credential-store-guard`: Blocks direct access to OS-backed credential stores such as Keychain, libsecret, and Windows Credential Manager.
- `env-sample-secret-guard`: Blocks real secrets from being written into samples, examples, and demo environment files.
- `git-credential-store-guard`: Blocks plaintext git credential storage and direct reads of git credential stores.
- `netrc-credential-guard`: Blocks direct reads and exports of .netrc credential files.
- `oauth-device-flow-guard`: Prompts when agent-driven device-code and browserless OAuth login flows try to mint delegated user access.
- `package-manager-auth-inline-guard`: Blocks live tokens and credentials pasted into package-manager auth files and config.
- `pre-push-scan`: Scans source files for likely secrets, internal network data, and connection strings before push.
- `protect-secrets-read`: Blocks reads and direct tool access to local secret files like .env, cloud credentials, SSH keys, and kube config.
- `registry-credential-guard`: Blocks direct reads and exports of package and container registry credential files.
- `release-key-guard`: Blocks reads and exports of release signing keys and provenance key material.
- `secret-diff-guard`: Blocks live connection strings and auth-bearing config content before they become part of the working diff.
- `secret-manager-abuse-guard`: Prompts when agents pull live secrets directly from Vault, cloud secret managers, or desktop password tooling.
- `test-fixture-secret-guard`: Blocks live tokens and private keys from being written into tests, fixtures, or snapshots.
- `token-broker-guard`: Prompts on live token minting, delegated session helpers, and cached auth-broker flows.
- `token-paste-guard`: Blocks likely live API tokens and private keys from being pasted into tool inputs or file edits.

### Supply Chain & Dependencies

Guards that watch package, registry, CI, artifact, and provider trust boundaries before dependency and release workflows turn into compromise.

- `artifact-poisoning-guard`: Blocks direct tampering with release artifacts, checksums, and signature material outside the normal packaging path.
- `ci-artifact-secret-upload-guard`: Blocks CI artifact uploads and release bundles that include secret-bearing files.
- `ci-secret-release-guard`: Blocks CI and release changes that widen token exposure, trust boundaries, or release permissions.
- `ci-self-hosted-runner-guard`: Blocks high-risk workflow patterns that combine self-hosted runners with untrusted PR triggers.
- `dependency-script-guard`: Blocks install-time and build-time dependency script changes that fetch or execute remote code.
- `package-lock-source-swap-guard`: Prompts when lockfiles or package source config shift to unreviewed registries or raw artifact hosts.
- `package-publish-guard`: Warns when the agent is about to publish packages, releases, or pushed artifacts outside the repo boundary.
- `public-artifact-secret-guard`: Blocks copying secrets and key material into public, build, release, or artifact directories.
- `registry-target-guard`: Blocks publish and login flows that target unexpected package or container registries.
- `terraform-provider-source-swap-guard`: Prompts when Terraform or OpenTofu provider sources move to unreviewed registries or namespaces.

### Git & Source Control

Guards that protect repository integrity, provenance, remotes, hooks, and source-distribution trust in everyday git workflows.

- `block-unsafe-git`: Blocks hook bypasses, force pushes to protected branches, and hard resets on protected branches.
- `git-attributes-filter-guard`: Blocks filter, smudge, and clean hooks injected through git attributes or git config.
- `git-history-rewrite-guard`: Blocks broad git history rewrite and purge flows that can destroy provenance and review context.
- `git-hook-persistence-guard`: Blocks risky execution and network behavior being added to git hook persistence paths.
- `git-remote-rewire-guard`: Prompts when git remotes are repointed to unreviewed hosts or raw IPs.
- `git-submodule-source-swap-guard`: Prompts when git submodule URLs move to unreviewed hosts or raw sources.
- `signed-commit-bypass-guard`: Blocks changes that disable commit or tag signing and weaken provenance checks.

### MCP, Plugins & Skills

Guards that keep MCP servers, tools, plugins, skills, and instruction files from becoming a hidden second control plane.

- `abuse-chain-defense`: Blocks remote-instruction writes, rule-override language in control files, and secret-plus-transfer command chains.
- `indirect-prompt-injection-guard`: Warns on hidden instructions, jailbreak text, encoded payloads, and smuggled prompt-injection content found in tool output.
- `instruction-override-bridge-guard`: Blocks trusted instruction files that tell the runtime to bypass Runwall or trust tool output over local policy.
- `instruction-source-dropper-guard`: Blocks remote content from being written directly into AGENTS, CLAUDE, skills, or Claude command files.
- `mcp-binary-dropper-guard`: Redacts upstream MCP responses that look like executable, archive, or second-stage payload material.
- `mcp-bulk-read-exfil-guard`: Prompts for review when an MCP tool call bundles multiple secret-like read targets into one request.
- `mcp-egress-destination-class-guard`: Blocks or prompts on MCP requests that target webhooks, paste sites, gist-like hosts, or blob storage according to outbound policy.
- `mcp-egress-policy-guard`: Prompts or blocks when an MCP request targets a destination outside the configured per-profile outbound policy.
- `mcp-egress-private-network-guard`: Blocks or prompts on MCP requests that target private IP space, localhost, or link-local destinations according to outbound policy.
- `mcp-install-source-allowlist`: Blocks MCP and plugin install sources outside a reviewed allowlist.
- `mcp-parameter-smuggling-guard`: Blocks MCP tool-call arguments that hide prompt overrides, encoded payloads, or inline execution chains.
- `mcp-permission-guard`: Blocks broad or high-risk MCP and tool permission grants in MCP control files.
- `mcp-response-prompt-smuggling-guard`: Redacts upstream MCP responses that contain hidden prompt injection or policy-override text.
- `mcp-response-secret-leak-guard`: Redacts upstream MCP responses that contain live secret or credential material.
- `mcp-response-shell-snippet-guard`: Blocks upstream MCP responses that contain fetch-and-execute chains, encoded shells, or staged interpreter snippets.
- `mcp-response-suspicious-url-guard`: Prompts for review when upstream MCP responses contain risky outbound URLs such as paste sites, webhooks, raw gists, or private endpoints.
- `mcp-secret-env-guard`: Warns when high-value secret environment variables are forwarded into MCP server definitions.
- `mcp-server-command-chain-guard`: Blocks dangerous download-and-execute or inline interpreter chains inside MCP server definitions.
- `mcp-tool-impersonation-guard`: Blocks upstream MCP tools that spoof trusted Runwall or control-plane tool names.
- `mcp-tool-schema-widening-guard`: Blocks sensitive MCP tools that suddenly widen into free-form schemas.
- `mcp-upstream-swap-guard`: Blocks inline gateway upstream entries that switch to remote, sideloaded, or scratch-path server sources.
- `plugin-exec-chain-guard`: Blocks dangerous download-and-execute or inline interpreter chains embedded in plugin hook and command definitions.
- `plugin-hook-origin-guard`: Blocks plugin hook commands that execute code from temp, download, scratch, or other paths outside the plugin trust boundary.
- `plugin-manifest-guard`: Blocks risky plugin and extension sources being added through manifest files.
- `plugin-surface-expansion-guard`: Blocks plugins that widen their hook surface through sensitive lifecycle command hooks or broad shell-plus-mutation coverage.
- `plugin-trust-boundary-tamper-guard`: Blocks plugins that try to weaken Claude, MCP, plugin, or Runwall control files after install.
- `plugin-update-source-swap-guard`: Blocks plugin update metadata that swaps reviewed sources to risky remote or scratch locations.
- `sideloaded-extension-guard`: Blocks sideloaded local plugin and extension installs from temp, download, archive, or unpacked paths outside reviewed sources.
- `skill-exec-chain-guard`: Blocks dangerous download-and-execute or inline interpreter chains embedded in skill and Claude command files.
- `skill-install-source-guard`: Blocks sideloaded or raw skill install sources outside a reviewed allowlist.
- `skill-multi-stage-dropper-guard`: Blocks trusted skill or instruction docs that embed fetch-save-execute or decode-then-run chains.
- `skill-trust-boundary-tamper-guard`: Blocks prompt-override and guard-bypass language being added to AGENTS, CLAUDE, skills, or Claude command files.
- `tool-capability-escalation-guard`: Blocks MCP tool definitions that combine broad shell, file, and network reach in one widened capability surface.
- `tool-origin-guard`: Blocks risky MCP or tool origins such as temp paths, shell-wrapper commands, and untrusted remote sources in tool config files.

### Runtime, Network & Egress

Guards that constrain outbound movement, runtime escape paths, droppers, and high-risk network behavior while staying quiet in normal dev work.

- `archive-and-upload-guard`: Blocks archive-and-transfer command chains that package sensitive or high-value material for outbound upload.
- `binary-payload-guard`: Blocks downloaded or decoded executable payloads from being staged for local execution.
- `block-dangerous-commands`: Stops remote shell piping, destructive permission changes, and a few high-confidence destructive commands.
- `cloud-metadata-guard`: Blocks access to cloud instance metadata endpoints that can expose credentials or identity context.
- `dns-exfiltration-guard`: Blocks DNS queries and lookups that carry encoded or sensitive material out of the workspace.
- `local-tunnel-guard`: Blocks public exposure of local services through tunnel and reverse-port-forward tooling.
- `local-webhook-guard`: Blocks webhook-style outbound sinks when they are used to move secrets, archives, or repo material.
- `network-exfiltration`: Blocks suspicious outbound transfer commands when they reference secret files, key material, or database dumps.
- `remote-script-dropper-guard`: Blocks remote content being dropped into script or executable paths in preparation for local execution.
- `repo-mass-harvest-guard`: Blocks bulk repo packing and enumeration patterns that look ready for export or staging.
- `tunnel-beacon-guard`: Blocks reverse tunnels, local exposure tools, and beacon-style remote access setup.
- `workspace-boundary-guard`: Blocks system-path and deep-parent traversal patterns that leave normal workspace boundaries.

### Infra & Production Access

Guards that make production, cluster, database, and infrastructure actions much harder to trigger accidentally or maliciously.

- `cluster-admin-binding-guard`: Blocks creation or application of cluster-admin role bindings and equivalent high-trust RBAC grants.
- `container-escape-guard`: Blocks privileged container launches, host mounts, and namespace abuse that turn containers into host escape paths.
- `container-socket-guard`: Blocks direct access to Docker, containerd, CRI-O, and Podman sockets.
- `dangerous-migration-guard`: Blocks destructive migration patterns such as data-loss flags, table drops, and reset flows.
- `devcontainer-trust-guard`: Blocks devcontainer and Codespaces-style config changes that weaken isolation or add remote setup execution.
- `docker-build-secret-leak-guard`: Blocks secret-bearing build args and secret-file mounts that would leak credentials into image builds or build logs.
- `kube-exec-prod-guard`: Blocks direct exec, attach, and debug access into production-like Kubernetes targets.
- `kube-secret-guard`: Blocks direct reads and edits of live Kubernetes secrets through kubectl command flows.
- `kubectl-port-forward-prod-guard`: Blocks port-forwarding against production-like Kubernetes targets.
- `prod-db-dump-guard`: Blocks dump and export commands aimed at production-like databases and customer data stores.
- `prod-db-shell-guard`: Blocks direct interactive database shell access when the target looks like production or customer data.
- `prod-target-guard`: Blocks direct mutating commands against production-like deploy and infrastructure targets.
- `production-shell-guard`: Blocks interactive shell access into production-like workloads and targets.
- `terraform-destroy-guard`: Blocks destructive infrastructure teardown commands before they hit Terraform, OpenTofu, Terragrunt, or Pulumi state.

### Trust, Persistence & Evasion

Guards that catch persistence, trust downgrades, log wiping, symlink hijacks, and other attempts to weaken the local security boundary first.

- `audit-evasion-guard`: Blocks shell history, event log, and Runwall audit trail clearing behavior.
- `config-tamper-guard`: Blocks edits that weaken Claude, MCP, or CI control files with bypass or wildcard-permission patterns.
- `credential-helper-downgrade-guard`: Blocks auth-helper changes that fall back to plaintext credential stores or disabled secure keychains.
- `hosts-file-tamper-guard`: Blocks local hosts-file remaps for high-trust infrastructure domains.
- `local-ca-trust-guard`: Prompts when the runtime tries to add new root or trust-anchor certificates to the machine.
- `log-poisoning-guard`: Blocks secret leaks and forged audit artifacts from being written into logs, reports, SARIF, or Runwall evidence files.
- `sandbox-escape-guard`: Blocks host-mount, namespace, and privileged-runtime patterns associated with sandbox escape attempts.
- `sandbox-policy-tamper-guard`: Blocks changes that weaken Docker, compose, and devcontainer isolation with privileged flags or host-linked options.
- `scheduled-task-persistence-guard`: Blocks recurring OS task, service, and launch-item registration that can be used for persistence.
- `shell-profile-persistence-guard`: Blocks suspicious downloader or execution payloads from being added to shell or PowerShell profile files.
- `ssh-agent-abuse-guard`: Blocks agent forwarding and SSH agent extraction patterns that widen key trust boundaries.
- `ssh-authorized-keys-guard`: Blocks agent-driven writes to authorized_keys and related SSH login trust material.
- `ssh-config-include-guard`: Blocks SSH config includes and indirection to temp, download, or otherwise unreviewed paths.
- `ssh-proxycommand-guard`: Blocks ProxyCommand, LocalCommand, and related SSH config hooks that create covert execution paths.
- `ssh-trust-downgrade-guard`: Blocks SSH commands and config changes that disable host verification or known-host trust checks.
- `sudoers-tamper-guard`: Blocks edits that weaken sudo policy or password requirements.
- `trusted-config-symlink-guard`: Blocks symlink redirection of trusted config, policy, and instruction files.

### Quality & Workflow

Guards that keep workflow integrity intact so the runtime cannot quietly suppress tests, evade review, or blur accountability.

- `context-chain-guard`: Adds subagent-aware runtime prompts and session-scoped risky chain detection without requiring whole-agent interception.
- `mass-delete-guard`: Blocks broad destructive delete patterns outside common generated-file cleanup directories.
- `post-edit-quality-reminder`: Suggests formatting, linting, and test commands based on the files the agent just touched.
- `protect-sensitive-files`: Warns after edits to risky files like package manifests, env files, workflows, and deploy config.
- `protect-tests`: Warns when the agent edits test files or introduces skip and focus markers that can silently reduce coverage.
- `unexpected-registry-login-guard`: Prompts when agents try to log into or reconfigure package registries outside the reviewed default set.

## FFU Pipeline A

- `mcp-secret-scope-guard`: block MCP configs that request secret scope outside declared need
- `oauth-token-exchange-guard`: block token exchange and delegated session minting flows that do not map to a reviewed identity broker
- `secret-redaction-guard`: require redacted examples instead of live secret examples in docs, fixtures, and generated samples

## FFU Pipeline B

- `tool-reputation-freeze-guard`: pin reviewed tool identities locally and force review before a trusted tool source can rotate underneath the same name
- `mcp-capability-overlay-guard`: detect when multiple MCP servers together create a toxic read-plus-exfil execution surface that no single server exposes alone
- `skill-approval-path-guard`: require reviewed install or update paths for skill bundles even when the source host looks legitimate
- `response-trust-escalation-guard`: stop tool output from convincing the runtime to treat newly returned hosts, binaries, or registries as trusted by default
