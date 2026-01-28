#!/usr/bin/env bash
set -euo pipefail

# your connect parameters
TRTYPE=rdma
ADRFAM=ipv4
TRADDR=192.168.1.4
TRSVCID=4420

# discover NQN automatically (as before)
NQN=$(nvme discover -t $TRTYPE -a $TRADDR -s $TRSVCID \
      | awk '/nqn/ {print $2; exit}')
nvme connect -t $TRTYPE -n $NQN -a $TRADDR -s $TRSVCID -o $ADRFAM

# wait for udev
sleep 1

# find the block device in the JSON listing
DEV=$(nvme list -o json \
    | jq -r --arg nqn "$NQN" --arg addr "$TRADDR" --arg svc "$TRSVCID" '
      .Devices[]
      | select(.SubsystemNQN == $nqn and .Transport == "RDMA" and .TRADDR == $addr and .TRSVCID == $svc)
      | .Name
    ')

if [[ -z "$DEV" ]]; then
  echo "could not find the newly‐attached device!"
  nvme disconnect -n "$NQN" || true
  exit 1
fi

echo "using device $DEV for dd"


echo "disconnecting $NQN"
nvme disconnect -n "$NQN"