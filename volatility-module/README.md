# Volatility Overlay for SGX

The `module.c` contains the structures that represent SGX enclave pages at kernel level. The overlay automatically handles the two Intel driver (i.e., isgx and DCAP).

To generate an overlay, we made a `run.sh` utility taking inspiration from here https://www.andreafortuna.org/2019/08/22/how-to-generate-a-volatility-profile-for-a-linux-system/.

```bash
cd ~/volatility-module
./run.sh
```