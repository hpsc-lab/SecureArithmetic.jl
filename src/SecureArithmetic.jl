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
export generate_keys, init_multiplication!, init_rotation!, init_bootstrapping!
export encrypt, decrypt, decrypt!, bootstrap!
export serialize_to_json_string, deserialize_from_json_string
export serialize_to_binary_file, deserialize_from_binary_file
export serialize_to_json_file, deserialize_from_json_file

# Query crypto objects
export level, capacity

# Memory management
export release_context_memory

# Multithreading
export enable_multithreading, disable_multithreading

include("types.jl")
include("operations.jl")
include("auxiliary.jl")
include("openfhe.jl")
include("unencrypted.jl")
include("arithmetic.jl")

end # module SecureArithmetic
