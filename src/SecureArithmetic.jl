module SecureArithmetic

using OpenFHE: OpenFHE
using Base.ScopedValues: ScopedValue, with

# Basic types
export SecureContext, SecureVector, PlainVector, PlainMatrix, SecureMatrix,
       PlainArray, SecureArray

# Keys
export PrivateKey, PublicKey

# Backends
export Unencrypted, OpenFHEBackend

# Crypto operations
export generate_keys, init_multiplication!, init_rotation!, init_bootstrapping!
export encrypt, decrypt, decrypt!, bootstrap!

# Query crypto objects
export level, capacity

# Memory management
export release_context_memory

# Multithreading
export with_multithreading, enable_multithreading, disable_multithreading

include("auxiliary.jl")
include("types.jl")
include("operations.jl")
include("openfhe.jl")
include("unencrypted.jl")
include("arithmetic.jl")

end # module SecureArithmetic
