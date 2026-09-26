# Running osreach against Canonical OpenStack (Sunbeam)

These steps assume a Sunbeam deployment (MAAS or manual) and a client machine
where the `sunbeam` CLI works, such as the one you run `sunbeam cluster list` on.
osreach only **reads** from the Neutron, Nova and Keystone APIs.

## 1. Install

```bash
python3 -m venv ~/osreach-venv && . ~/osreach-venv/bin/activate
pip install 'osreach[openstack] @ git+https://github.com/<you>/osreach'
# or, from a checkout:  pip install -e '.[openstack]'
```

## 2. Credentials

osreach uses openstacksdk. To see every project's ports and security groups,
it needs admin credentials:

```bash
sunbeam openrc > ~/admin-openrc      # keep this file private
. ~/admin-openrc
openstack network list               # sanity check
```

If your public endpoints use a private CA, export `OS_CACERT=/path/to/ca.pem`.
You can also use an entry in `clouds.yaml` with `--cloud NAME`.

## 3. Snapshot and analyse

```bash
mkdir -p ~/osreach-data && cd ~/osreach-data
osreach snapshot -o $(date +%F).snapshot.json

osreach exposure  $(date +%F).snapshot.json            # what the internet can reach
osreach lint      $(date +%F).snapshot.json            # redundant/dead rules, port security off
osreach query     $(date +%F).snapshot.json --from internet --to all --proto tcp --port 22
osreach check     $(date +%F).snapshot.json my-policy.yaml
```

`sunbeam configure` usually creates an external network (often called
`external-network`) and a demo project. Both show up in the analysis like any
other. If your "external" network is a lab or corporate range (for example
`192.168.x.x`), `internet` will exclude it because it is private address
space. Ask about it explicitly with `--from cidr:192.168.0.0/16`.

### The reference MAAS layout

Canonical's [example physical configuration](https://canonical.com/openstack/docs/latest/reference/example-physical-configuration/)
uses two physical networks. Many deployments copy it as-is:

| Network | Example CIDR | Carries | Questions to ask osreach |
|---|---|---|---|
| Generic | `172.16.1.0/24` | MAAS, Juju and Sunbeam controllers, API endpoints (`<name>-internal-api` / `<name>-public-api` ranges), the Sunbeam client | `--from cidr:172.16.1.0/24` (who on the management side reaches VMs) and `--to cidr:172.16.1.0/24` (can VMs reach MAAS/Juju/APIs?) |
| External (`neutron:physnet1`) | `172.16.2.0/24` | floating IPs and router gateways for **every** project | cross-project traffic between projects with separate routers always hairpins through here |
| Project networks | e.g. `192.168.0.0/24` | per-project VM traffic | isolation between projects |

Both physical networks are private address space, so `internet` only matters if
your edge actually forwards public traffic to the external network.

For `--to cidr:172.16.1.0/24`, osreach assumes the external network's upstream
gateway routes to the generic network (an over-approximation). A "reachable"
result means the cloud itself does not stop the traffic. Whether your physical
router does is a separate check, for example `nc -vz <maas-ip> 5240` from a
test VM.

### What osreach does not see on Sunbeam

* **Load balancers** (`sunbeam enable load-balancer`, the Octavia OVN provider):
  traffic to a VIP's floating IP is not modelled yet. Check
  `openstack loadbalancer list`; if it's empty, nothing is missed.
* **Hosts on the generic network** are not Neutron ports, so they only appear
  as `cidr:` endpoints.
* **TLS**: if you ran `sunbeam enable tls ca|vault` and the snapshot fails with
  a certificate error, export `OS_CACERT` pointing at the cloud's CA. The
  snap-packaged `openstack` CLI may work without it while openstacksdk in your
  virtualenv does not.

## 4. Drift detection

Run `scripts/nightly.sh` from cron or a systemd timer on the client machine.
It snapshots the cloud, checks your policy, and diffs against yesterday's
snapshot, exiting non-zero if access grew:

```cron
15 2 * * *  . $HOME/admin-openrc && $HOME/osreach/scripts/nightly.sh $HOME/osreach-data $HOME/policy.yaml
```

## 5. Publishing results from a private cloud

Raw snapshots contain your addressing plan, project and instance names, and
UUIDs. **Never commit them.** The repository's `.gitignore` excludes
`*.snapshot.json` and `snapshots/`. To share a real snapshot (for example as a
paper artefact, a bug report or a test fixture), anonymise it first:

```bash
head -c 32 /dev/urandom | base64 > ~/.osreach-anon.key     # keep private; reuse for diffs
osreach anonymize 2026-09-24.snapshot.json -o cloud-anon.json --key-file ~/.osreach-anon.key
```

Anonymisation works as follows:

* IPv4 addresses are mapped by a keyed prefix-preserving permutation, so
  subnets, rule prefixes and "is this public?" all survive. Every osreach
  result on the anonymised file equals the original result up to renaming
  (see `tests/test_anonymize.py`).
* Prefix preservation means the *structure* of your address plan is visible
  (how many subnets there are, how they nest), and high-order bits leading
  towards private ranges are kept by design. Treat the output as
  pseudonymised, not as secret-free.
* Names are hashed unless you pass `--keep-names`. Pass it only if the names
  themselves are harmless.

Also keep the CI for a public repo on GitHub-hosted runners. Don't attach a
self-hosted runner on the cloud's network to a public repository, because
anyone opening a pull request could run code inside your network.
