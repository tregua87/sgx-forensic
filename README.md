# SGX MEMORY FORENSIC PROJECT

This project collects a set of tools for performing forensic memory analysis of SGX enclaves.

The project is structured as follow:
- [LiME for SGX machines](./lime): `./lime` contains a custom LiME version that traverses and dumps the SGX enclaves structure allocated by the kernel. Moreover, the tool attempts at donwloading the encalve page content if they are in DEBUG mode. The project handles the two Intel SGX driver released so far (i.e., isgx and DCAP).
- [Volatility Overlay Utilities](./volatility-module): `./volatility-module` contains the tools to create a Volatility Profile enabled to inspect the SGX encalve structures allocated at kernel side.
- [Volatility SGX Plugin](./volatility-plugin): `./volatility-plugin` contains a volatility plugin that analysis the enclave memory layout, extracts the ECALL/OCALL/ECREATE, and provides other forensic information.

The project is maintained by:
- Flavio Toffalini (https://github.com/tregua87)
- Andrea Olivieri (https://github.com/IridiumXOR/)
