# H1 effort retrospective

Section 9 of the plan (`h1-privilege-split-plan.md`) was written *before*
any of sections 3–6 were implemented, an estimate, not a record. Now that
the core work is merged, this is the actual record, checked against real
commit and merge dates rather than guessed. Where useful, this also draws
the distinction the plan's own estimate couldn't: calendar time between
merges (which includes real-world gaps between work sessions) versus
actual active effort within each section.

## The original estimate, verbatim

> Roughly: 1 day to instantiate the `system-agent` module skeleton and
> move the write logic over largely as-is; 1 to 2 days for the DB
> contract, migration, and web-app-side rewiring (`NetworkSecurityController`,
> repository, deleted classes, updated tests); 1 day for the
> systemd/ACL/sudoers provisioning and a staging run-through. Call it a
> multi-day to one-week effort for one person familiar with the codebase,
> not a multi-week rewrite.

## What actually happened, by merge date

| Section | PR | Merged | What the estimate said |
|---|---|---|---|
| Pre-H1 hardening (C1/C2/H2/H3/H4) | #7 | 2026-07-15 | not part of the H1 estimate at all |
| 3: Database contract | *(direct to main, no separate PR)* | 2026-07-19 | "1 to 2 days" |
| 4: `system-agent` module | #8 | 2026-07-22 | "1 day" |
| 5: Privilege provisioning | #9 | 2026-07-23 | "1 day" |
| 6: Web app cutover | #10 | 2026-07-31 | *(not separately estimated, folded into section 3's "web-app-side rewiring")* |

## Where the estimate held

**Section 3 (database contract): the estimate was right**, 07-18 to
07-19, roughly two days, landing squarely in the "1 to 2 days" the plan
predicted. What the estimate didn't predict, and couldn't have, was
*why* those two days were needed: not writing the `agent_status`
migration itself (that part really did take under an hour), but
discovering that `V1`, `V2`, and `V4` had **never once successfully run**
against this schema in the project's history (`AUTO_INCREMENT` and bare
`ALTER COLUMN` are both rejected by H2's `MODE=PostgreSQL` parser, and
nothing had ever exercised Flyway for real to catch it), plus two
entirely missing tables (`blocked_domains`, `network_scan_results` and
friends) that Hibernate's `ddl-auto=update` had been silently
papering over in every environment tested so far. The estimate assumed
"write one migration"; the actual work was "discover and fix four
pre-existing latent bugs, incidentally while writing one migration." Same
day count, very different reason for it.

**Section 5 (privilege provisioning): the estimate significantly
undercounted, and the reason is instructive.** "1 day for the
systemd/ACL/sudoers provisioning and a staging run-through" assumed
writing the provisioning artifacts was the work. Writing them took well
under a day. What the estimate didn't account for: **there was no staging
environment to run the "staging run-through" against**, so the actual
validation happened via CI simulation, built specifically because it
didn't exist yet, and that CI simulation then surfaced six real,
previously-unknown bugs, one at a time, each requiring its own diagnosis
and fix cycle: lost executable bits, a CI-runner umask assumption, an
over-broad sudoers validation, two separate fixed-`sleep`-instead-of-poll
timing bugs, a missing-optional-dependency crash-loop
(`ReadWritePaths=/etc/dnsmasq.d` with no soft-path prefix, a genuine
production bug the estimate had no way to anticipate), and a JDK-version
mismatch on the CI runner. None of these were "provisioning work" in the
sense the estimate meant; all of them were exactly the kind of finding
that only surfaces from actually running something for real instead of
reading it, which was the entire premise of insisting on CI simulation
over trusting the files by inspection. The estimate was for writing the
artifacts. The actual cost was proving them, and that cost was real,
just invisible to an estimate written before anyone had tried.

## Where the estimate didn't apply at all

**The gap between section 5 (merged 07-23) and section 6 starting
(07-30), roughly a week, is calendar time, not effort.** The plan's
"multi-day to one-week" framing was about active work, and conflating
that with elapsed calendar time (which includes normal pauses between
work sessions, unrelated priorities, etc.) would overstate how long the
actual implementation took. Section 6 itself, once picked back up,
merged within two days (07-30 to 07-31), consistent with the pace of
every other section, which is why this retrospective reports merge dates
rather than trying to reverse-engineer "hours spent," that number isn't
recoverable from git history and estimating it would just be a second
guess layered on the first one.

## The most useful thing this retrospective actually shows

Every section that involved **writing new code against a spec** (the
`agent_status` schema, the `system-agent` module's classes) landed close
to or under its estimate. Every section that involved **proving something
true in an environment nobody had tested yet** (Flyway actually running
end to end for the first time ever; the systemd unit actually starting
under real sandboxing for the first time ever) took longer than
estimated, and did so by surfacing genuine, previously-invisible bugs
that a smaller, code-only estimate structurally couldn't have accounted
for. If this project does another privilege-boundary-shaped piece of work
in the future, the actionable lesson isn't "estimates are wrong", it's
"budget separately, and generously, for the first real end-to-end run of
anything that has never been end-to-end run before, that's where the
actual unknowns live, not in the code you already know how to write."
