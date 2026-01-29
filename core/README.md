# Miden core
This crate contains core components used by Miden VM. These components include:

* Miden VM instruction set, defined in the [Operation](./src/operations/mod.rs) struct.
* Miden VM program kernel, defined in [Kernel](./src/kernel.rs) struct which contains a set of roots of kernel routines.
* Miden VM program structure, defined in [Program](./src/program.rs) struct and described [here](https://docs.miden.xyz/miden-vm/design/programs).
* Miden VM program metadata, defined in [ProgramInfo](./src/program.rs) struct which contains a program's MAST root and the kernel used by the program.
* Input and output containers for Miden VM programs, defined in [StackInputs](./src/stack/inputs.rs) and [StackOutputs](./src/stack/outputs.rs) structs.
* Constants describing the shape of the VM's execution trace.
* Various minor utility functions used by other VM crates.

## Acknowledgements
The `racy_lock` module found under `core/src/utils/sync` is based on the [once_cell](https://crates.io/crates/once_cell) crate's implementation of `race::OnceBox`.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
