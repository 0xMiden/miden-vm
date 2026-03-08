# Protocol Example

This example project is intended to demonstrate how the Miden protocol artifacts (as of this writing) would be modeled using the new project system.

The Miden protocol consists of the following components:

* The transaction kernel library
* The userspace library that wraps the transaction kernel, abstracting over the actual `syscall`s.
* The transaction kernel program, i.e. the executable that sets up the kernel environment and provides the entrypoint for the protocol.
* An alternative transaction kernel program used for special use cases, but for this example, the only relevant aspect is that a project may have multiple executables that share a common core.
* A shared library providing utility functions that may be used in the kernel, userspace, or executables.

This setup could be modeled a few different ways:

1. A workspace with each component listed above in its own project. This works fine, but may be overkill in terms of organizataional boilerplate.
2. A workspace with a couple of projects to break things up into more logical units, which is what is demonstrated here:
  a. A library project containing the shared library code used by all the other components
  b. The transaction kernel and its executables
  c. The userspace kernel library which depends on the transaction kernel library
