# Deploy a ZigChain node on AWS

Three ways, fastest first.

## 1. One click (CloudFormation)

[![Launch Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home#/stacks/create/review?templateURL=https://raw.githubusercontent.com/codenlighten/zigchain/main/deploy/aws/cloudformation.yaml&stackName=zigchain)

The stack launches an EC2 instance that builds the node into a container and runs
it as a self-restarting service with a persistent block log. Pick your options
(instance type, port, mine yes/no, an optional `SeedPeer` to join an existing
network) and create the stack. The **Outputs** tab shows the node's public
`ip:port` once it is up (allow a few minutes for the first build).

> If the console rejects a non-S3 `templateURL`, use method 2, or upload
> `cloudformation.yaml` to your own S3 bucket and point the button at it.

## 2. AWS CLI

```sh
aws cloudformation deploy \
  --stack-name zigchain \
  --template-file deploy/aws/cloudformation.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides Mine=true P2PPort=9000
# read the outputs (public ip:port):
aws cloudformation describe-stacks --stack-name zigchain \
  --query 'Stacks[0].Outputs' --output table
# tear down:
aws cloudformation delete-stack --stack-name zigchain
```

Join an existing network instead of starting a new chain:

```sh
aws cloudformation deploy --stack-name zigchain-2 \
  --template-file deploy/aws/cloudformation.yaml \
  --parameter-overrides Mine=false SeedPeer=<existing-ip>:9000
```

## 3. Docker anywhere (including EC2 by hand)

The image is a ~9 MB statically-linked binary on Alpine.

```sh
docker build -t zigchain .
docker run -d --name zigchain --restart unless-stopped \
  -p 9000:9000 -v zigchain-data:/data \
  -e ZIGCHAIN_MINE=true \
  zigchain
docker logs -f zigchain
```

Environment variables (see `deploy/docker-entrypoint.sh`):

| var | default | meaning |
|---|---|---|
| `ZIGCHAIN_PORT` | 9000 | P2P listen port |
| `ZIGCHAIN_DATADIR` | /data | persistent block log (mount a volume) |
| `ZIGCHAIN_MINE` | false | `true` to mine |
| `ZIGCHAIN_PEER` | — | peer(s) to dial, comma-separated `ip:port` |
| `ZIGCHAIN_NAME` | zigchain | log label |
| `ZIGCHAIN_BLOCKS` | — | stop after N blocks (unset = run forever) |

## What it provisions

- An EC2 instance (Amazon Linux 2023) running the node in Docker with
  `--restart unless-stopped` (survives crashes and reboots).
- A **separate, retained** `gp3` EBS volume (`DeletionPolicy: Retain`) mounted at
  `/var/lib/zigchain` for the block log, so the chain **survives instance and
  stack teardown** (and the node also re-syncs from peers, and replays the log
  on restart — defence in depth). If the volume can't be mounted, boot falls
  back to the root volume rather than failing.
- A security group opening the P2P port to the internet (and SSH only if you
  pass a key pair).

The deployed node is built in **ReleaseSafe** (`-Dnode-safe=true` in the
`Dockerfile`) — integer-overflow and bounds checks trap deterministically, which
matters for code validating untrusted network input.

## Production notes

- **Restrict `SSHLocation`** to your own IP, and pass a `KeyName` only if you
  need shell access.
- The image pins the exact Zig toolchain (`Dockerfile` `ARG ZIG_VERSION`) from a
  durable mirror, so builds are reproducible.
- The retained data volume keeps the chain after teardown; delete it by hand
  (or via its `DataVolumeId` output) when you truly want to discard the chain.
- **Caveat:** the EBS mount logic follows AWS/Nitro best practice (wait for the
  device, format on first boot, `nofail` fstab entry) but has been validated for
  template structure only, not against a live instance. Do a test launch in a
  throwaway account before relying on it.
