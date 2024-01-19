module SecureArithmetic

using OpenFHE: OpenFHE

# Basic types
export SecureContext, SecureVector, PlainVector

# Backends
export Unencrypted, OpenFHEBackend

# Crypto operations
export generate_keys, init_multiplication!, init_rotation!, init_bootstrapping!
export encrypt, decrypt, decrypt!, bootstrap!

include("types.jl")
include("openfhe.jl")
include("unencrypted.jl")
include("arithmetic.jl")

end # module SecureArithmetic
