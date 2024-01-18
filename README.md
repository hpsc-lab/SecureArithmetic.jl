# SecureArithmetic.jl

[![Docs-stable](https://img.shields.io/badge/docs-stable-blue.svg)](https://securearithmetic-jl.lakemper.eu/stable)
[![Docs-dev](https://img.shields.io/badge/docs-dev-blue.svg)](https://securearithmetic-jl.lakemper.eu/dev)
[![Build Status](https://github.com/sloede/SecureArithmetic.jl/workflows/CI/badge.svg)](https://github.com/sloede/SecureArithmetic.jl/actions?query=workflow%3ACI)
[![Coveralls](https://coveralls.io/repos/github/sloede/SecureArithmetic.jl/badge.svg)](https://coveralls.io/github/sloede/SecureArithmetic.jl)
[![Codecov](https://codecov.io/gh/sloede/SecureArithmetic.jl/branch/main/graph/badge.svg)](https://codecov.io/gh/sloede/SecureArithmetic.jl)
[![License: MIT](https://img.shields.io/badge/License-MIT-success.svg)](https://opensource.org/license/mit/)

SecureArithmetic.jl is a Julia package for performing cryptographically secure arithmetic
operations using fully homomorphic encryption. It currently provides a backend for
OpenFHE-secured computations using [OpenFHE.jl](https://github.com/sloede/OpenFHE.jl), and
an unencrypted backend for fast verification of a computation pipeline.


## Getting started

### Prerequisites
If you have not yet installed Julia, please [follow the instructions for your
operating system](https://julialang.org/downloads/platform/).
[SecureArithmetic.jl](https://github.com/sloede/SecureArithmetic.jl) works with Julia v1.8
and later on Linux and macOS platforms, and with Julia v1.9 or later on Windows platforms.

### Installation
Since SecureArithmetic.jl is not yet a registered Julia package, you can install it by
executing the following commands in the Julia REPL:
```julia
julia> import Pkg; Pkg.add("https://github.com/sloede/SecureArithmetic.jl")
```
If you plan on running the examples in the
[`examples`](https://github.com/sloede/SecureArithmetic.jl/tree/main/examples) directory,
you also need to install OpenFHE.jl:
```julia
julia> import Pkg; Pkg.add("OpenFHE")
```

### Usage
The easiest way to get started is to run one of the examples from the
[`examples`](https://github.com/sloede/SecureArithmetic.jl/tree/main/examples) directory by
`include`ing them in Julia, e.g.,
```julia
julia> using SecureArithmetic

julia> include(joinpath(pkgdir(SecureArithmetic), "examples", "simple_real_numbers.jl"))
================================================================================
Creating OpenFHE context...
CKKS scheme is using ring dimension 16384

================================================================================
Creating unencrypted context...
================================================================================
simple_real_numbers with an OpenFHE context
Input x1: (0.25, 0.5, 0.75, 1, 2, 3, 4, 5,  ... ); Estimated precision: 50 bits

Input x2: (5, 4, 3, 2, 1, 0.75, 0.5, 0.25,  ... ); Estimated precision: 50 bits


Results of homomorphic computations:
x1 = (0.25, 0.5, 0.75, 1, 2, 3, 4, 5,  ... ); Estimated precision: 43 bits

x1 + x2 = (5.25, 4.5, 3.75, 3, 3, 3.75, 4.5, 5.25,  ... ); Estimated precision: 43 bits

x1 - x2 = (-4.75, -3.5, -2.25, -1, 1, 2.25, 3.5, 4.75,  ... ); Estimated precision: 43 bits

4 * x1 = (1, 2, 3, 4, 8, 12, 16, 20,  ... ); Estimated precision: 41 bits

x1 * x2 = (1.25, 2, 2.25, 2, 2, 2.25, 2, 1.25,  ... ); Estimated precision: 41 bits

x1 shifted circularly by -1 = (0.5, 0.75, 1, 2, 3, 4, 5, 0.25,  ... ); Estimated precision: 43 bits

x1 shifted circularly by 2 = (4, 5, 0.25, 0.5, 0.75, 1, 2, 3,  ... ); Estimated precision: 43 bits

================================================================================
simple_real_numbers with an Unencrypted context
Input x1: [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
Input x2: [5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]

Results of homomorphic computations:
x1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
x1 + x2 = [5.25, 4.5, 3.75, 3.0, 3.0, 3.75, 4.5, 5.25]
x1 - x2 = [-4.75, -3.5, -2.25, -1.0, 1.0, 2.25, 3.5, 4.75]
4 * x1 = [1.0, 2.0, 3.0, 4.0, 8.0, 12.0, 16.0, 20.0]
x1 * x2 = [1.25, 2.0, 2.25, 2.0, 2.0, 2.25, 2.0, 1.25]
x1 shifted circularly by -1 = [0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0, 0.25]
x1 shifted circularly by 2 = [4.0, 5.0, 0.25, 0.5, 0.75, 1.0, 2.0, 3.0]
```


## Referencing
If you use SecureArithmetic.jl in your own research, please cite this repository as follows:
```bibtex
@misc{schlottkelakemper2024securearithmetic,
  title={{S}ecure{A}rithmetic.jl: {S}ecure arithmetic operations in {J}ulia using fully homomorphic encryption},
  author={Schlottke-Lakemper, Michael},
  year={2024},
  howpublished={\url{https://github.com/sloede/SecureArithmetic.jl}}
}
```


## Authors
SecureArithmetic.jl was initiated by [Michael Schlottke-Lakemper](https://lakemper.eu) (RWTH
Aachen University/High-Performance Computing Center Stuttgart (HLRS), Germany), who is also
its principal maintainer.


## License and contributing
SecureArithmetic.jl is available under the MIT license (see [LICENSE.md](LICENSE.md)).
Contributions by the community are very welcome! For larger proposed changes, feel free
to reach out via an issue first.
