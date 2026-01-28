## Configuration

Initialize the repo `git clone --recurse-submodules https://github.com/spcl/hazel`.

Copy the device you are interested in to `spdk\module\bdev\`. Then apply the corresponding patch, e.g., `git apply integrity.patch` inside the `spdk` directory. 

Prepare SPDK for compilation by running in the SPDK directory `./scripts/pkgdep.sh`, `./configure --with-rdma=mlx5_dv --with-crypto`. Then compile with `make -j`.

Configure the corresponding addresses if needed by running `sudo ip addr add <ip> dev <dev>`.

You might need to also configure your drives to use 64B metadata. For that:
```
sudo nvme delete-ns /dev/nvmeX --namespace-id=1
sudo nvme create-ns /dev/nvmeX --nsze=<size> --ncap=<size> --flbas=3 --dps=0 --nmic=0
sudo nvme attach-ns /dev/nvmeX --namespace-id=1 --controllers=0
sudo nvme format /dev/nvmeXn1 --ses=1 --lbaf=3 --ms=1
```
Then verify with `sudo nvme list`. Change `flbas` to 2, and `ms` to 0, to revert.

Configure the drives by running `sudo HUGEMEM=<size> scripts/setup.sh` (can be reversed by `sudo HUGEMEM=<size> CLEAR_HUGE=yes scripts/setup.sh reset`). We used a size of 55000 for remote and 23000 for local. Note, you might also need to change the runtime env setup (`*.conf`) for the correct PCIe address of your disk.

## Runtime

On the remote, you can run `sudo ./build/bin/nvmf_tgt -c ../runtime/simple_freshness_nvme.conf -m 0x1fe 2>&1 | tee log.log`.

On local `sudo ./build/bin/spdk_tgt -c ../runtime/integrity_device.conf -m 0xffff`.

On the tenant, you can run `sudo nvme discover -t rdma -a <ip> -s 4420` and `sudo nvme connect -t rdma -n "nqn.2016-06.io.spdk:cnode2" -a <ip> -s 4420` to attach the disk.

## Blake3 dependency

For both the integrity and freshness devices, we require a secure hashing function. For that purpose, we selected libblake. To compile it, use the official Blake3 implementation available [here](https://github.com/BLAKE3-team/BLAKE3), and compile a `libblake3.so` placed in the integrity/freshness device directories. We provide the binaries from our systems, but these might not work for you. You also might need to change the linker flags in `Makefile` to point to the correct directory (check `.patch` files). 

## Zero initialization

We zero-initialized the disks by attaching them freshly formatted to the tenant and running `sudo dd if=/dev/zero of=/dev/nvme1n1 bs=1M`, where `nvme1n1` was found using `sudo nvme list`.
