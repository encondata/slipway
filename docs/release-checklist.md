# Release checklist: data safety and environments (PR #7)

This release takes Tower's Slipway from `main` (migration 0006) to `sirdar`: the app manifest (0007), data safety (0008) and environments (0009). The container applies migrations itself when it starts, so the database backup in step 2 is the way back.

## 1. ServerSherpa first (BaseCampV3, branch `slipway-manifest`)

- [ ] Commit and push the phase 3 changes on `slipway-manifest`: `slipway.yml`, `deploy/stack/ss-stack`, `deploy/stack/env.example`, `deploy/tests/test_ss_stack.py`, and the new `deploy/stack/test-server-role.sh`. Its deploy tests pass (251).
- [ ] Decide which branch the Tower instances deploy. Slipway reads `slipway.yml` from the instance's own branch, so an instance on BaseCampV3's `main` gets the data features only after `slipway-manifest` is merged there.

## 2. Back up Slipway on Tower

In `/mnt/user/slipway`:

```bash
docker compose exec -T db pg_dump -U slipway -Fc slipway > /mnt/user/slipway/slipway-before-0009.dump
```

- [ ] The dump file is not empty.
- [ ] `.env` has `SLIPWAY_ENCRYPTION_KEY` set. Stored snapshots are encrypted with it; keep a copy of it with the dump.

## 3. Ship

- [ ] Push `sirdar` and merge PR #7 into `main`.
- [ ] Run the installer on Tower. It also creates `data/files` (owned by uid 10001, mode 700) for stored snapshots.

```bash
curl -fsSL https://raw.githubusercontent.com/encondata/slipway/main/install.sh | bash
```

- [ ] `docker compose logs slipway | grep -i "running upgrade"` lists 0006 -> 0007, 0007 -> 0008 and 0008 -> 0009.
- [ ] Sign in. The Hosts page shows the old "environment" values under **Label**. Instances and their deploys look as before.

## 4. Settings for environments

- [ ] Settings -> Integrations -> Switchyard: set **Traffic address** (where Switchyard serves the sites, such as its LAN IP). Without it, the post-switch check is skipped with a warning.
- [ ] The Switchyard API key has `hosts.list`, `hosts.get`, `hosts.create`, `hosts.update`, `hosts.delete`, `config.preview` and `config.apply`.
- [ ] Optional: Settings -> Integrations -> Cloudflare: zone, public IP, and a token limited to that zone with Zone DNS Edit and Zone Read. Use a test zone first.
- [ ] Hosts that will run slots: if a host has more than one network, set its **LAN address** to the address it reaches the data server from.

## 5. Phase 2 checks on a real host

Deploy BaseCampV3 `slipway-manifest` twice, then:

- [ ] Back up now
- [ ] take a snapshot
- [ ] reset from it
- [ ] roll back a commit with a failing migration
- [ ] download it with a passphrase and import it into a second Slipway
- [ ] seed a new instance from it
- [ ] Start over after a failed first deploy
- [ ] an instance with `STACK_EXTERNAL_DATA=1` shows its data lives outside the host, and still backs up

After each, a user signs in with their own password and 2FA.

## 6. Phase 3 checks on real hosts

Three LAN hosts with pinned keys (blue, green, data), Switchyard with a traffic address, Cloudflare with a test zone:

- [ ] Create `uat` as Blue/Green with DNS and `tls_mode auto`. The chain deploys the data server (its DNS records and `spaces` host appear), then blue, activates blue and adds the starter content. Back up now carries the environment's identity keys.
- [ ] Deploy a commit with an expand migration to green while blue serves, then activate green. The same session and 2FA still work.
- [ ] Switch back (while a Back up now runs) and forward again. Switch back once more and deploy a fix to green: the lag check refuses it until confirmed.
- [ ] Deploy a commit whose migration fails to the idle slot, then Discard it (nothing restored). Repeat and Roll back instead (both slots stop; the failed one stays stale).
- [ ] Restore a backup (both slots stopped; the lead slot migrated and started before the job ends). Make the lead slot's start fail once and see the job fail and hold. Take a snapshot and seed a second environment from it.
- [ ] Remove green, add it on another host with the data server updated, and deploy to it.
- [ ] Stop Switchyard during an Activate (the names are put back), then Resolve.
- [ ] Delete `uat`: only the records and hosts Slipway made are gone; volumes and backups stay on the data host.
- [ ] A standalone ServerSherpa instance on one of the hosts deploys and publishes as before throughout.
- [ ] Restart Slipway during the chain (after the data server deploy's `finish`): the environment page shows the notice, and its button continues the chain.

## If it goes wrong

The old code can't run on the new schema (0009 renames the host column), so go back with both the code and the database:

```bash
cd /mnt/user/slipway && docker compose stop slipway
```

```bash
docker compose exec -T db pg_restore -U slipway -d slipway --clean --if-exists < /mnt/user/slipway/slipway-before-0009.dump
```

```bash
git checkout -q -f 13b1954 && docker compose up -d --build
```

`13b1954` is `main` before this release. Snapshots stored after the upgrade stay in `data/files`, but the old code doesn't read them.
