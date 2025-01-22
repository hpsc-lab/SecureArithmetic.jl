module SecureArithmetic

using OpenFHE: OpenFHE

# Basic types
export SecureContext, SecureVector, PlainVector, PlainMatrix, SecureMatrix,
       PlainArray, SecureArray

# Keys
export PrivateKey, PublicKey

# Backends
export Unencrypted, OpenFHEBackend

# Crypto operations
export generate_keys, init_multiplication!, init_rotation!, init_bootstrapping!,
       init_array_rotation!
export encrypt, decrypt, decrypt!, bootstrap!

# Query crypto objects
export level, capacity

# Memory management
export release_context_memory

include("types.jl")
include("operations.jl")
include("openfhe.jl")
include("unencrypted.jl")
include("arithmetic.jl")

end # module SecureArithmetic
