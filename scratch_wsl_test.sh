#!/bin/bash
set -e
cd /mnt/c/fyp-project/caliper

export DEBIAN_FRONTEND=noninteractive

echo "Checking dependencies..."
if ! command -v qemu-system-x86_64 >/dev/null; then
    echo "Installing QEMU..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq qemu-system-x86 curl
fi

if ! command -v limactl >/dev/null; then
    echo "Installing Lima..."
    LIMA_VER="1.0.0"
    curl -fsSL "https://github.com/lima-vm/lima/releases/download/v${LIMA_VER}/lima-${LIMA_VER}-Linux-x86_64.tar.gz" -o lima.tar.gz
    sudo tar -C /usr/local -xzf lima.tar.gz
    rm lima.tar.gz
fi

echo -e "\n=== deploy/check-hardware.sh output ==="
./deploy/check-hardware.sh
echo "========================================="

echo -e "\nBringing up cell 2..."
limactl start --name caliper-cell2 deploy/cell2-baseline.yaml || true
echo -e "\nBringing up cell 4..."
limactl start --name caliper-cell4 deploy/cell4-unpatched.yaml || true

echo -e "\n=== Cell 2 (Baseline) ==="
limactl shell caliper-cell2 -- containerd --version || echo "Failed"
limactl shell caliper-cell2 -- runc --version || echo "Failed"
limactl shell caliper-cell2 -- apt-mark showhold || echo "Failed"
echo "========================="

echo -e "\n=== Cell 4 (Unpatched) ==="
limactl shell caliper-cell4 -- containerd --version || echo "Failed"
limactl shell caliper-cell4 -- runc --version || echo "Failed"
limactl shell caliper-cell4 -- apt-mark showhold || echo "Failed"
echo "========================="

# Clean up
limactl delete --force caliper-cell2 caliper-cell4 >/dev/null 2>&1 || true
