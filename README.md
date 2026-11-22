# LeakScan (Forge 1.16.5, client-side)

## Building

1. Download the official Forge 1.16.5 MDK (36.2.x), take `gradlew` and `gradle/` from it.
2. Put the contents of this archive next to them (`build.gradle`, `settings.gradle`, `src/`), then run `./gradlew build`.
3. If your Forge version in `build.gradle` (1.16.5-36.2.39) differs, adjust it.
4. The finished jar is `build/libs/leakscan-1.0.0.jar` → put it into the client's `mods/`.

For JDK details and common build pitfalls see the "Building: JDK details (pitfalls)" section at the end of this file.

## Usage

Join the server with an ACCOUNT WITHOUT PERMISSIONS (not an operator!). A leak = what an ordinary player can see.
Repeat for each permission group and change the label with `.ls label helper` so the reports can be compared.

Chat commands (intercepted locally, never sent to the server):
- `.ls status` — counters
- `.ls report` — write the report now (also written when you leave the server)
- `.ls probe defaults | roots | /text~` — extra probes (`~` = space)
- `.ls label <name>` — permission profile label

Files: `<gameDir>/leakscan/sessions/<server>_<time>/` → `report.md` (compact digest),
`report-full.md` (full format), `findings.json`, `packets.jsonl`, `probes.jsonl`, `full-lists/`.
Settings: `<gameDir>/leakscan/config.json`, probe list: `probes.txt`.
`silentMode=true` — silent mode: auto-probes don't start, automatic chat messages are suppressed
(`.ls` replies still work — they are local); checks are started manually via `.ls probe defaults`.

## Code architecture (src/main/java/dev/leakscan)

- `PacketSniffer` — a Netty handler (`addBefore("packet_handler", ...)`) for both directions; it also
  performs the byte-level `leakscan`→`optifine` replacement in the outgoing `fml:handshake`.
- `Session` — one connection = one session = one log folder; packet dispatch by (cached) simple
  class names via `Refl.classNameOf`; login phase, ping host, `notifyUser` (suppressed in silentMode).
- `PhaseDetector` — phase splitting (JoinGame has weight 2 and triggers alone; Respawn+CommandList
  is suppressed within 30 s after a detected death; early lock-free exit for non-markers).
- `Analyzer` — all rules and findings: regex RULES, channels (incl. `vv:`/`voicechat:secret`
  parsers), the vanish triple diff, latency criteria, ping findings, timing x3, consolidations.
  `Refl` — access to packet fields BY TYPE (SRG-safe, metadata is cached).
- `Prober` — the tab-complete probe queue, budget, backoff pause, retest counter (bypassing the
  seen-dedup and the budget).
- `Reporter` — `report.md` (compact) + `report-full.md` (full) + JSONL logs + full-lists.
- `PingProbe` — a server-list ping at connect time (same host:port, separate socket, daemon thread).
- `ChannelPatternAnalyzer`/`ChannelDb` — cross-session byte-level channel DB per host;
  `GlobalChannelIndex` — channel union across hosts (`_global.json`);
  `ResourcePackFingerprintDb` — global sha1 DB (resource packs + ping favicon).

Config `config.json` (all flags): `autoProbe`, `autoDefaultProbes`, `autoNamespaceProbes`,
`autoRootArgProbes`, `startDelayMs=3000`, `probeIntervalMs=250`, `probeTimeoutMs=5000`,
`maxProbes=400`, `pauseAfterConsecutiveTimeouts=8`, `probePauseCanaryMs=30000` (backoff base),
`notifyInChat`, `label`, `externalCommandsFile`, `channelPatternAnalysis`, `channelDbMaxSamplesPerChannel`,
`channelDbSampleBytes`, `deepProbeOnEmpty`, `deepProbeTokens`, `timingBaselineEnabled`,
`timingBaselineProbe`, `scanTeamPackets`, `scanSoundNamespace`, `scanKeepAliveTiming`,
`scanDimensionCodec`, `resourcePackFingerprintDb`, `scanBossBar`, `scanScoreboardObjectives`,
`scanChatSenderUuid`, `scanTpsFromTimeUpdate`, `vanishTripleDiff`, `silentMode`, `pingOnJoin`,
`pingTimeoutMs`, `hideFromFmlHandshake`, `globalChannelIndex`, `compactReport`.

## Report phase splitting (server switching behind a proxy)

Switching backends behind Velocity/BungeeCord does not create a new TCP connection and does not
guarantee any specific packet: one proxy/fork will send a full `JoinGame`, another gets by with
`Respawn`, and the command tree, difficulty, tags, recipes etc. may arrive in any combination.
That is why `PhaseDetector` is not tied to a single packet: it weights the burst of "login"
packets in a sliding window (~1.2 s). `JoinGame`/`Respawn` trigger on their own, the rest
(`CommandList`, `ServerDifficulty`, `TagsList`, `UpdateRecipes`, `PlayerAbilities`, `HeldItemChange`,
`WorldBorder`, `ScoreboardObjective`/`DisplayObjective`) — only when at least two different types
arrive in a row. The very first burst after joining is not counted as a switch (it's a normal login).

Note: the marker list has since been narrowed down — see rounds 3 and 8 below. The current list:
`JoinGame` alone, or `Respawn`+`CommandList` (suppressed for 30 s after a detected death, because
vanilla re-sends the command tree after death).

Each detected phase is a separate `## Server/phase N` in `report.md`: its own brand, worlds,
`entityId` from JoinGame, command tree, channels and findings. The total server counter in the
report header is cross-checked against how many times Forge itself fired `LoggedInEvent` (an extra
cross-check signal only — server switching is not detected from it, since behind a proxy it does
not always fire again).

## Channel pattern DB (cross-session)

`<gameDir>/leakscan/channel-db/<server>.json` accumulates BETWEEN sessions on the same server
(keyed by host, not session), so patterns are visible even if the channel only carried 1-2 packets
in a single visit. Settings in `config.json`: `channelPatternAnalysis` (on/off),
`channelDbMaxSamplesPerChannel` (how many DISTINCT payloads to keep per channel),
`channelDbSampleBytes` (how many leading bytes to store).

`report.md` gets a "Channel payload patterns" section: for each channel the fixed/variable length
is heuristically analyzed, samples are compared byte-by-byte (which bytes never change, which do),
with attempts to recognize 16-byte UUIDs, 1/2/4/8-byte counters (monotonically growing — looks
like a tick/sequence-id) and text fields (including constant ones — e.g. a hardcoded host that
never changes, which doesn't mean it isn't worth seeing). Text fields are run through the same
regex rules as the rest of the traffic. If there are fewer than 2 distinct samples so far, the
section explicitly says "not enough data yet" instead of staying silent.

## Changes after the second real-world test round

- **Channel MEDIUM-finding spam removed**: previously every observed plugin channel created its own
  finding ("Channel seen: X"), so a report with 9 channels produced 9 nearly identical lines. Now
  there is ONE finding per phase, "Plugin/mod channels seen (N)", with all channels and hints in
  the evidence.
- **`minecraft:register`/`unregister` no longer enter the channel pattern DB** as a separate
  "channel": that is a list of NAMES of other channels, not anyone's payload, and it used to look
  like one confusing channel instead of explicit `bungeecord:main`, `voicechat:...` etc. (those
  are already parsed line by line and appear under "Channels of this phase").
- **Similar large lists are grouped, not compared pairwise**: if 5 aliases of one command
  (`/ci`, `/clean`, `/clear`, `/clearinvent`, `/clearinventory`) match each other byte-for-byte
  and all differ from `/recipe` by the same few items, that is now ONE finding with a merged alias
  list, not 5 copies. Differences consisting only of `*`/`**` (wildcard placeholders, not content)
  don't count in the diff and don't create a finding when there are no real differences.
- **"4 bytes" does not mean "a number"**: a short ASCII field is now checked BEFORE the numeric
  interpretation (otherwise a 4-byte text tag would never reach it). If the values at that position
  do not grow monotonically, the wording honestly says "may be a number, bit flags, a hash
  fragment or a random id" instead of confidently calling it "a number".
- **Respawn+PlayerAbilities is a normal respawn/portal transition, not a server switch.**
  `PlayerAbilities` was removed from the phase-switch markers entirely (it flies on every respawn
  anyway), and `Respawn` was downgraded to a weak signal: it no longer triggers alone, at least one
  other "login" packet is required (command tree, difficulty, tags, recipes, held item, world border).
- **Empty phases (pre-login/limbo with no content) are explicitly marked** in report.md: if a phase
  has no brand, no channels, no commands and no findings, a warning is written at the top that this
  is most likely a splash screen / a moment before the sniffer was installed, not a separate server.

## Changes after the third real-world test round

Some of the third-party AI review's remarks were confirmed on the data, some were not (verified
against `packets.jsonl`/`probes.jsonl`, not taken on faith). Below is what was actually wrong and
what was fixed.

**Respawn still triggered a phase switch.** Confirmed: `SServerDifficultyPacket` (and, by
extension, likely `PlayerAbilities`/`HeldItemChange`/`WorldBorder` too) turned out to be part of
the normal world re-sync on respawn/portal, not login-only. The marker list was narrowed a lot:
now a phase switch is `JoinGame` (alone) or the `Respawn`+`CommandList` pair — forwarding the
command tree has nothing to do with world re-sync, it's about permissions/server software.

**Hidden players in ARBITRARY commands.** Previously the hidden-player search only worked for a
hardcoded list (`/msg`, `/tell`, `/w`...). On a real server it turned out that ~40 other commands
also accept the online player list as an argument (`/mv`, `/ruda`, `/apl`, `/bal`...), and this
used to be reported as "nearly identical large lists" (4-5 separate MEDIUMs). Now:
- similar large lists are merged into one component (connected components, not just adjacent
  pairs — otherwise 4 mutually similar groups produce 6 copies of the same finding);
- the component's common "core" is treated as player names only if a noticeable part of the core
  actually matches what was seen in the live tab list at some point during the scan (otherwise an
  ordinary item registry like `item_42`/`custom_relic` accidentally matches the username format and
  is falsely counted as "players" — that happened in one test before this check was added);
- discrepancies between commands are cross-checked against everyone who was ever visible in the
  tab list during the whole scan (not just "right now" — a player may have joined/left mid-scan):
  if a name never appeared — HIGH "hidden player"; if it appeared at least once — just normal
  churn, no finding at all.
- if the only difference is "*"/"**" (placeholders), checked separately: in the attached data they
  were already correctly filtered out of the diff (the filter from the previous round worked), but
  not out of the similarity grouping — that part was true, it only affects clustering, not content.

**"N commands with the same list" without an explicit diff.** If after grouping a component has
only one exact-match group (nothing to compare with) or the differences within a component reduced
to zero after subtracting the core and wildcard noise — a light LOW finding "N commands answer with
the same list" is still produced if there are at least 10 such commands (threshold in code), for
reference only.

**RTT between phases.** A separate comparison of the median RTT between adjacent phases was added:
if it differs by 1.5x or more — a separate line in the report ("looks like a different network hop").
Anomalies WITHIN one phase (timing-channel candidates) were counted before; these are different things.

**Brand as a "string", not a "range of byte lengths".** Previously all minecraft:brand-like
channels (payload = just a VarInt string) went through the generic byte-level analysis, and three
different brands from three backends turned into an incomprehensible "length from 18 to 56 bytes".
Now such a channel is first checked for "is it just a whole string" — and if so, the report gets
the DISTINCT DECODED VALUES, not a range of byte lengths.

## Changes after the fourth round (third-party AI review)

All 10 points were verified against actual data (`packets.json`/`probes.json`/`findings.json`),
not taken on faith. 4 of 10 turned out to be real bugs; the rest were either misreadings of the
data or intentional behavior (explained below; code was not changed where there was no problem).

**Confirmed and fixed:**

- **Cyrillic and §-codes were mangled in packet previews.** `ByteUtil.runs()` only understood
  single-byte ASCII and broke the string at every Cyrillic/§ byte ("Your server (Purpur)" became
  " (Purpur)"). Rewritten to proper UTF-8 parsing (2/3/4-byte sequences). Separately, the preview
  in `packets.jsonl` now first tries a structural VarInt+UTF-8 parse (`ByteUtil.preview`) so the
  service length byte is not included when its value accidentally lands in printable ASCII range
  (that happened too: a leading "/" from a length byte that landed in printable ASCII range).
- **Large suggestion lists were truncated OUT OF EXISTENCE.** Both `probes.jsonl` (300 items) and
  evidence in `findings.json` (200 items) independently cut a large list, and the full version
  existed NOWHERE (not just in the report, as it had seemed). Now, above the threshold, the full
  uncut list is saved to `<session>/full-lists/<name>.txt`, and the first evidence line is a
  pointer to that file — it survives truncation because it comes first.
- **Garbage suggestions like `;`, `?`, `!`, `,`** (the server really sends them) are excluded from
  "commands outside the tree"/"hidden commands" findings — a string without a single letter/digit
  cannot be a command name.
- **407 probes wasted in limbo/auth phases where there are no answers at all** (checked: 53/53
  probes in phases 0-1 of that session timed out). An adaptive pause was added: after N (default 8)
  consecutive timeouts with not a single answer, the phase's auto-probes are suspended (manual
  `.ls probe` still works and lifts the pause). Marked in the report with a separate line so it is
  visible that the budget wasn't burned for nothing. (This pause was later redesigned into a
  self-resuming exponential backoff — see round 8.)

**Softened, not fully rebuilt** (an honest capability limit without collecting repeat statistics):
timing candidates are now marked as single outliers with an explicit advice to re-check manually
via repeated probes before drawing conclusions; the threshold was raised slightly (3×median
instead of 2×, +40ms instead of +30ms).

**Minor wording fixes:** `LoggedInEvent from Forge` is explicitly marked as a client-side (not
server-side) event; the tab-complete recommendation explicitly separates "leaking the fact that a
command exists" from "leaking the permission to execute it".

**Checked and NOT changed** (the remark was not confirmed on the data):
- *"Brand is duplicated between phases (Purpur in phases 2 and 3)"* — the data was misread: in
  phase 2 the brand is `<fork A>`, in phase 3 it is `<fork B>` — DIFFERENT values in
  DIFFERENT phases, exactly as intended (each phase = a separate environment). Likewise
  LimboFilter (phase 0) and LimboAuth (phase 1) — different values, not duplicates.
- *"fml:hs/wdl:* may be client-side/echo channels"* — the sniffer processes `minecraft:register`
  only on the INCOMING (server→client) direction, so these channels cannot structurally get there
  as "client-side" — the direction is unambiguous.
- *"hex is cut off in packets.json for register"* — by design: the `hex` field has its own short
  cap (64 bytes) for log compactness, while the `text` field (its own, wider cap) and `report.md`
  process the FULL payload — nothing is lost, these are just different fields with different
  purposes.

## Round five: new modules

Processed 5 of your suggestions + 5 "modules" from another AI. What was technically sound and
stayed within read-only tab-complete/passive observation was implemented; what wasn't — explained
below, nothing silently skipped.

**Implemented:**
- **Deep probes on empty answers (your idea 1 + Module 4, safe part).** If a command REALLY exists
  in the tree but `/cmd ` returned nothing — we try to bypass the block using the same tab-complete
  means: a plausible 2nd argument (`LuckPerms`/`EssentialsX`/`WorldGuard`, list in config), a
  different case of the command name, a double trailing space. If any of that works — a HIGH
  finding "the block is bypassed by an extra argument/mutation" naming the exact probe that worked.
  Mutations touching the BEGINNING of the command (null byte, space right after "/") are
  deliberately not done — see below.
- **Brand idea 2 (light version).** No full cross-session timing DB (agreed with your
  self-correction — network/TPS/chunk jitter at minimum complicates the statistics). Instead, one
  always-probed deliberately non-existent command (`timingBaselineProbe` in config) as an RTT
  reference within the current session — shown in the report next to the median.
- **Team packet (your idea 4, part 1).** `STeamsPacket` sometimes names a player who is not in the
  live tab list (e.g. a scoreboard team update for a vanished player, so their own prefix renders
  correctly) — a HIGH finding, with an honest caveat about a possible race during normal
  join/leave.
- **Custom sound namespaces (Module 3, adapted to 1.16.5).** There is no sound registration packet
  in 1.16.5 (a later-version feature), but `SPlaySoundPacket` carries the sound as a
  `ResourceLocation` directly — a foreign namespace is visible without any registration. Findings
  are consolidated into one per phase (same logic as channels).
- **Dimension codec NBT (your idea 5).** From `JoinGame`, `CompoundNBT` is extracted via
  type-based reflection (no need to know exact SRG method names), `.toString()` is scanned for
  foreign `namespace:...`. I do not claim to identify the SPECIFIC server core from tag structure —
  I have no verified base of such signatures, that would be guesswork. What is implemented:
  honest detection of custom dimensions/biomes even when the brand is faked as vanilla.
- **KeepAlive jitter (Module 2).** Purely passive statistics of `SKeepAlivePacket` intervals
  (mean, stddev, % close to multiples of 50ms) — without a ready-made "this is Paper/Purpur"
  conclusion: I cannot confidently confirm the specific claim from Module 2, so the report shows
  raw numbers and an honest note that interpretation is ambiguous.
- **Resource pack SHA-1 across hosts (Module 5).** A separate GLOBAL (not per-host, unlike
  channel-db) DB `resourcepack-fingerprints.json`: if the same byte-for-byte pack pops up on
  another host/IP — a HIGH finding, an almost 100% signal of the same network under another brand.

**Not implemented, with reasoning:**
- **Module 1 (TCP frame size as a leak).** Technically unsound: Netty/Minecraft do not "carry
  over" the old buffer's size onto the new one — the packet is encoded strictly according to its
  final (post-plugin-hook) content; residual metadata of the original array physically cannot be
  on the wire.
- **`RawMutatedTabPacket` with a raw `0x00` bypassing `PacketBuffer.writeString()`.** Declined:
  this is not "unusual but legal input" like the other probes, but an intentionally invalid (from
  the protocol's point of view) packet crafted specifically to bypass the server's built-in input
  validation (`readUtf()` in modern versions explicitly rejects strings with control characters) —
  in effect a mini-fuzzer of the network parser, not an audit probe, with a real risk of the
  server dropping the connection. Its usefulness is also smaller than it seems: most sane blocks
  do `.trim()` before comparison, and `trim()` strips a trailing `\u0000` exactly like a normal
  space — so the already-implemented double space hits the same thing without breaking the protocol.
- **The "/  command" mutation (space right after the slash).** You checked it yourself — it
  doesn't work. It's Brigadier: a literal doesn't match if there is a space in its place; that is
  server behavior, not a client limitation, so no packet trick will help.

## Round six: the triple diff and more packets

- **"/ command" (space after the slash).** I admit my earlier wording was wrong — you had not
  actually tested it, it was theory. There is no risk (a normal valid string, not a protocol
  violation), so it was added as one more tried mutation — a real server will show whether it works.
- **`RawMutatedTabPacket` with a raw `0x00` — still not doing it.** Same reasoning as before:
  `readUtf()` in modern versions rejects control characters; this is not "unusual input" but an
  intentionally invalid packet bypassing the protocol's input validation, with a risk of the
  connection being dropped. Agreed that the idea (null byte) was a bad one — settled there.
- **Vanish triple diff (chat join/leave ↔ PlayerInfo ADD/REMOVE ↔ entity spawn).** The strongest
  new check: if a player entity physically spawned (visible to nearby players) but was never in
  PlayerInfo (the tab list) — HIGH, meaning the model/hitbox wasn't hidden at all even though the
  tab list was hidden correctly. Weaker: the player appeared in the tab list but there was no
  public "X joined the game" — MEDIUM (may just be a custom join message, not necessarily vanish);
  the comparison runs ONLY if at least one join was successfully parsed in the same phase
  (otherwise there is nothing to compare with, not "everyone is hidden").
- **Team packet: numeric name prefix ("00_admins").** A typical trick of forced tab-list sorting
  plugins (TAB and the like) — the very fact of such a name reveals them. LOW finding.
- **Sender UUID in system messages.** If a "system" message has a non-zero sender UUID — it may be
  someone's command sent on behalf of a player, not a real broadcast. If that UUID was already seen
  via PlayerInfo — it resolves to a name immediately.
- **Scoreboard objectives — internal names.** A consolidated finding (one per phase, not one per
  name) listing all observed internal objective names.
- **TPS from world age increments in TimeUpdate.** Mean/min/max per phase. "Uptime via age reset"
  from the original idea was NOT done — world age is persistent in the world save and a process
  restart does NOT reset it (that would be a false premise), not "the mod couldn't handle it".

## Round seven: gap analysis and two real bugs

You were right on all three points. In order:

**Console `/say` and automatic broadcasts.** Checked the logic: truly automatic messages (console,
a scheduled plugin task) have a zero sender UUID — the console/timer simply has nothing to attach,
so the `!sender.equals(new UUID(0,0))` check never touches them. A non-zero UUID almost always
means a PLAYER sent the message (e.g. an admin via `/say`), not a bot — that is exactly what the
finding covers. The wording was made explicit so it is clear from the report itself, not only from
the code.

**Citizens and other NPC plugins — that was a real bug, thanks.** The triple diff would have taken
EVERY NPC for a hidden player: Citizens NPCs have exactly the same signature (player-type entity,
spawn without a PlayerInfo entry) that I had laid down as a vanish indicator. Fixed: if there are
many "phantom" entities at once (3+) — this is almost certainly systematic NPCs, not a mass vanish,
so severity is lowered to LOW and Citizens is explicitly named as the likely cause in the text.
Even with 1-2 phantoms (where it is more likely a really hidden player) there is now an explicit
NPC-plugin caveat — previously there was none at all, and the finding sounded like a 100% verdict
although it isn't.

**The idea list was longer than I reported — also fair.** A complete reconciliation of all items
from both of your lists, nothing hidden:

| Idea | Status |
|---|---|
| Scoreboard objectives (internal names) | ✅ Done |
| BossBar: text | ✅ Done (via the generic scanText) |
| BossBar: UUID for cross-session identification | ❌ Not done — boss bar UUIDs are usually regenerated on every spawn, not a stable identifier unlike a resource pack sha1; questionable value |
| TimeUpdate → TPS | ✅ Done |
| TimeUpdate → uptime via age reset | ❌ Not done — age is persistent in the world save, a process restart does not reset it; that would be a false premise |
| PublicBukkitValues in item/entity NBT | ❌ Not done — the NBT is nested inside an ItemStack, not a direct packet field; needs recursive traversal with cycle protection; a separate, riskier task |
| Triple diff (chat/PlayerInfo/spawn) | ✅ Done, the NPC bug fixed in this round |
| Team: numeric name prefix ("00_") | ✅ Done |
| Team: collision rule / nametag visibility / glow color | ❌ Not done — just a few more `String` fields mixed in with the team name/prefix/suffix; type-based reflection cannot reliably tell them apart, and guessing by field position risks building a feature on a wrong assumption |
| Header/Footer: animation frequency | ✅ Done in this round |
| Scoreboard update rate (packets/s) | ✅ Done in this round (via `SUpdateScorePacket`) |
| Chat sender UUID (1.16) | ✅ Done |
| World-tagged sessions (extra splitting inside a phase by current world) | ❌ Not done — phases already split by backend/environment; finer splitting INSIDE one phase by a specific world is a standalone feature with its own uncertainty (when to count a "world change" for finding purposes) that I don't want to add in a hurry |
| Module 1: TCP frame size | ❌ Not done — technically unsound (see the previous round) |
| Module 4: null byte | ❌ Not done — risk of the connection being dropped (see the previous round) |
| Module 4: trailing §r | ✅ Added in this round — previously silently dropped without explanation, which was wrong |
| Module 4: `\n` (line feed) | ❌ Not done — unlike §, it is a control character; there are reasons to believe the same validation that cuts null bytes may cut it too — the same risk profile as the null byte, with no extra benefit |

## Round eight (2026-09-30 .. 10-06): dead branches, pause-forever, and a big upgrade

Fixes in this round were verified on real sessions (three live servers: a limbo-chain one, a rate-limited one, a heavily rate-limited one) and on a
local test stand; key decisions with reasoning:

- **The PlayerInfo branch of the triple diff had been dead all along.** `SPlayerListItemPacket$AddPlayerData`
  (1.16.5, verified against the decompiled class) has NO `UUID` field — only a `GameProfile`.
  Type-based search for a `UUID` field always returned null, so the whole branch was silent: 0
  `S_PLAYER_LIST_ITEM` records in the logs even on servers with online players (verified on
  a busy test server: 107 spawns, 0 records, 24 real players ended up as "phantoms"). Fix: the UUID is
  taken from `GameProfile.getId()`. After the fix: phantom findings disappeared where players were
  real, and `playerInfoAdded` finally fills up.
- **`scanDimensionCodec` was also dead:** JoinGame in 1.16.5 has no `CompoundNBT` fields — the
  codec is already decoded into `DynamicRegistries.Impl` objects. Now we walk the registries
  (dimension_type, biome) via type-based reflection (SRG-safe) and extract namespaces from the
  keys. Verified locally with a datapack providing `leakscan:custom`.
- **"8 stuck probes" = pause-forever.** `pauseAfterConsecutiveTimeouts=8` assumed "8 timeouts in a
  row = dead limbo", but rate-limited servers (one dropped ~45% of tab-completes, another
  up to 86%) produce a run of 8 by chance, and the pause could only be lifted manually. A
  "canary" was implemented first (a dummy probe for a non-existent command every 30 s) — IT DID
  NOT WORK: such servers never answer tab-complete for non-existent commands, the answer never
  comes (0 `auto-probe-resumed` events across all sessions). Final design: the canary is dropped,
  the pause is an exponential backoff 30s→60s→120s→240s (cap); after it expires the queue resumes
  by itself and the timeout counter resets; on the first answer the backoff resets to 30s. In a
  genuinely dead limbo this keeps budget usage at 8 probes per interval.
- **Respawn after death falsely triggered a phase again** (vanilla re-sends the command tree after
  death — confirmed by a local test). Solution: we track death (`SUpdateHealthPacket` health=0)
  and suppress the Respawn+CommandList burst within 30 s of a detected death. Behind a proxy this
  is not maskable — there is no death there.
- **The login phase is analyzed**: `SCustomPayloadLoginPacket` — the FULL Forge server mod list is
  parsed from `fml:handshake` (S2CModList: varint discriminator + varint count + mod id strings;
  the parser honestly refuses on an unexpected format); login kicks (BotFilter in limbo) are
  captured separately.
- **Pre-login ping at connect** (PingProbe): the SAME host:port the player connects to is pinged
  (a separate socket, at attach time). Collected: `version.name` (forks write their own name — a
  leak BEFORE login), favicon (sha1 → shared fingerprint DB: same favicon on another IP = same
  network), `players.sample` (cross-checked against the tab list over the session — hidden online
  in the ping; §-decorations instead of names are filtered by format), Forge `modinfo` (the
  server's mod list without joining). Disable with `pingOnJoin=false` if the anti-bot dislikes
  extra connections.
- **UPDATE_LATENCY as a vanish vector**: hidden players keep receiving ping updates. Honest
  criteria: ≥3 updates MORE THAN 5 s AFTER removal from the tab list, or a UUID that was never in
  any phase's tab list; own UUID and publicly departed players ("left the game" — finally using
  the data collected since round six) are excluded.
- **Timing candidates are re-verified automatically (x3)**: a candidate is RTT > max(3×median,
  median+40). Three retests do not consume the main budget; if the retest median is above the
  threshold → a "confirmed" finding, below → "it was a freeze" and the candidate is removed from
  the report. Retests do not pollute the base measurements' median. (Has not yet fired in the
  field — there were no outliers.)
- **Global channel index** `channel-db/_global.json`: union across hosts (channel → which hosts +
  total packets; payload samples are taken from the per-host DBs). `minecraft:*` are excluded
  (everyone has them — not a signal).
- **Stealth from FML logs**: verified by bytecode — `C2SModListReply` sends the server the list of
  ALL client mods (`ModList.get().getMods()`), it cannot be disabled by config. Solution: in the
  outgoing `fml:handshake` the bytes `leakscan` are replaced with `optifine` (same length — the
  VarInt prefixes remain structurally intact). Plus `displayTest="IGNORE_ALL_VERSION"` in mods.toml.
- **silentMode**: auto-probes don't start, automatic chat notifications are suppressed (`.ls`
  replies remain — they are local). Checks are started manually: `.ls probe defaults`.
- **Report split**: `report.md` is a compact digest (top-10 TL;DR with grouping of same-type
  findings, one line per finding, phase metrics on one line, only confirmed timing), the full old
  format lives in `report-full.md`, everything as before — in `findings.json`.
- **"Commands outside the tree" consolidated** into one finding per phase (previously 5 probes =
  5 identical HIGHs; on one server 10 of 16 HIGHs were one leak).
- Channel payload quotes in the "Channels seen" finding + `ByteUtil.sanitizeInline` (control
  characters, backticks, `|` — markdown/JSON cannot be broken by any payload).
- Hot-path optimizations: a class field cache and a `ClassValue` simple-name cache in `Refl`
  (previously `getDeclaredFields()`+`setAccessible()` and a string allocation on EVERY packet),
  a lock-free early exit in `PhaseDetector`; class-file debug info trimmed to `source,lines`
  (stack traces with line numbers preserved).

## Round nine (2026-10-10): exploring popular plugin sources

Popular plugin sources were studied (ViaVersion, LuckPerms, AuthMe, Simple Voice Chat, Matrix,
WorldEdit/WorldGuard, Grim, Dynmap, DiscordSRV, TAB). Key points:

- **`vv:server_details` (ViaVersion)** — tells the client the server's NATIVE version. All three
  test "1.16.5" servers were really 1.18-1.18.1. A separate "Server is masquerading as…" finding.
- **`luckperms:update`** — permission-change envelopes travel between backends and the proxy
  THROUGH arbitrary players' connections (Bukkit: `Iterables.getFirst`, no filtering and NO
  channel-registration check — Bukkit only checks registration on the plugin inbound side). The
  client sees BOTH directions: incoming envelopes (we are the "pipe" outward) and outgoing (the
  proxy delivers someone else's update through us — logged as `C_CUSTOM_PAYLOAD`). No
  `minecraft:register` is NEEDED (it was implemented and then removed as a useless trace).
  Spoofing is closed: LP on the proxy drops client packets via a source check and absorbs them;
  without LP on the proxy the channel is open, but pluginmsg sync is enabled manually and exists
  only for sync — without the proxy relay it is dead (topic closed, discussed separately).
  Content: `{"id","type","content"}` — types update(empty)/userupdate(user UUID)/log(action text)/
  custom; the actual permission changes are NOT transmitted.
- **`authme:main`** — symmetric: `{event type, NAME}` — the whole network's authorization status
  travels through other players' pipes.
- **`voicechat:secret` (Simple Voice Chat)** — a SecretPacket to every player: personal secret,
  port, UUID, MTU, distance (double), keepAlive, groups, allowRecording and voiceHost. A decoder
  is in the mod; a BARE IP in voiceHost while connecting via a domain → HIGH "reveals the machine's
  real IP" (a real case: the server was joined by domain, while the voice chat handed out a bare IP:port).
- **`matrix:geyser`** — the only channel of the cracked Matrix 7.25.1; Bedrock player names; the
  channel's presence in the register list = a Matrix+Geyser marker.
- **TAB** — the `TAB-Scoreboard` objective is a constant in the sources → a separate LOW finding.
- **Clean (no channels)**: WorldGuard, Grim (packetevents, server-side), Dynmap. WorldEdit —
  `worldedit:cui` (a presence marker). EssentialsX filters vanish from tab-complete
  (`canInteractWith`).
- The "permission node in a denial message" rule (like `you need essentials.fly`) → MEDIUM. The
  SocialSpy-prefix rule is NOT done: the prefix is configurable in the plugin's config — relying
  on something not hardcoded is pointless.
- General conclusion: ANY inbound channel registered by a plugin appears in the server's
  `minecraft:register` — a free software fingerprint; the mod parses the register list line by line.

## What it does

**Passively** (a sniffer in the Netty pipeline before `packet_handler`, sees everything before
vanilla processing):
- login phase: `fml:handshake` → the full Forge server mod list; login kicks; compression;
- pre-login ping at connect (same host:port, separate socket): `version.name`, favicon sha1
  (global cross-host DB), `players.sample` (cross-check vs the tab list over the session), Forge
  `modinfo`;
- JoinGame: brand (per phase), worlds, dimension codec (foreign namespaces of dimensions/biomes
  via `DynamicRegistries`), ints;
- plugin channels in BOTH directions: known-protocol parsing (`vv:server_details` → the server's
  native version with a masquerade finding, `voicechat:secret` → voice server address/secret/
  settings with HIGH for a bare IP behind a domain, `luckperms:update`, `authme:main`); for the
  rest — a payload quote in the finding + a byte-level cross-session DB (`channel-db/<host>.json`)
  with heuristic analysis (constants/counters/UUIDs/text) and a cross-host global index
  (`_global.json`); `minecraft:register` is parsed line by line (a software fingerprint);
- tab/players: PlayerInfo ADD/REMOVE/UPDATE_LATENCY, entity spawns, team packets, join/leave chat
  → the vanish triple diff + latency criteria + the ping sample;
- resource pack (URL + sha1, global cross-host DB), header/footer, boss bar, scoreboard objectives
  (including `TAB-Scoreboard`), custom sounds (namespace), system messages (sender UUID), TPS from
  world age, KeepAlive statistics, header/footer and scoreboard update rates;
- all strings (including channel payloads and suggestions) go through regex rules: internal IPs,
  filesystem paths, stack traces, build strings, secrets, webhooks, URLs, permission nodes in
  denial messages.

**Actively — ONLY tab-complete (CTabCompletePacket), nothing is executed:**
- auto-probes from probes.txt + `/plugin:` namespace probes for discovered namespaces;
- deep probes when a tree command answers empty: a plausible 2nd argument, different case, double
  space, "/ command", trailing `§r` (beginning mutations — null byte and friends — are
  DELIBERATELY absent, see round five);
- timing: candidates (RTT > max(3×median, median+40)) are automatically re-verified with 3
  repeats; a freeze is discarded, a stable one becomes a finding; repeats don't consume budget;
- responses with id >= 1_000_000 are intercepted and not shown to the vanilla client;
- a pause after 8 timeouts in a row is an exponential backoff with auto-resume (see round eight).

**Control**: `.ls status | report | label <name> | probe defaults | roots | /text~`.
Session files: `report.md` (compact) + `report-full.md` (full) + `findings.json` + `packets.jsonl`
+ `probes.jsonl` + `full-lists/`. Config: `config.json`, probes: `probes.txt`.

## Limitations

- Early play packets may arrive before the sniffer is installed — there is a fallback (the
  ClientPlayNetHandler state); the "Coverage" section of the report shows what was captured. The
  login phase (server list ping before connecting, the Forge handshake) is analyzed via separate
  paths (PingProbe + login packets); the handshake itself starts after LoginSuccess — the sniffer
  is already in place by then (the connecting screen is caught by ticks).
- Timing x3 re-verification has not yet fired in the field (no outliers) — the mechanism awaits
  its first real candidate. Death-based phase suppression is verified locally only.
- The `fml:handshake` mod list parsing and the `leakscan`→`optifine` replacement have not been
  verified on a live Forge server (all test servers were Bungee/Velocity).
- On anti-bot servers an extra ping connection or a probe stream may lead to a kick without a kick
  packet (observed in the field) — knobs: `pingOnJoin`, `startDelayMs`, `probeIntervalMs`.

## Building: JDK details (pitfalls)

1. TWO Java installations are needed: Gradle itself runs under a 64-bit JDK 17 (point `JAVA_HOME`
   at it), while compilation goes through a Java 8 toolchain pinned in `gradle.properties` to the
   path of a full JDK 8 on your machine. JRE-style installs (e.g. `jre1.8.0_451`) lack `tools.jar`
   (fine for running the game, NOT for building); Gradle's auto-detection may pick a 32-bit JDK 8
   from Program Files (x86) which cannot allocate the heap — hence "slideshow" and failures.
2. Command: `JAVA_HOME="<path to jdk-17>" ./gradlew build --offline` (works offline from the
   ForgeGradle cache). The finished jar: `build/libs/leakscan-1.0.0.jar` → into the client's `mods/`.
3. If your Forge version in `build.gradle` (1.16.5-36.2.39) differs — adjust it.
