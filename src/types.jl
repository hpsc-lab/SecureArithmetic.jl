abstract type AbstractCryptoBackend end

struct SecureContext{CryptoBackendT <: AbstractCryptoBackend}
    backend::CryptoBackendT
end

function Base.show(io::IO, v::SecureContext)
    print("SecureContext{", backend_name(v), "}()")
end

struct SecureVector{CryptoBackendT <: AbstractCryptoBackend, DataT}
    data::DataT
    length::Int
    context::SecureContext{CryptoBackendT}

    function SecureVector(data, length, context::SecureContext{CryptoBackendT}) where CryptoBackendT
        new{CryptoBackendT, typeof(data)}(data, length, context)
    end
end

Base.length(v::SecureVector) = v.length
function Base.show(io::IO, v::SecureVector)
    print("SecureVector{", backend_name(v), "}(data=<encrypted>, length=$(v.length))")
end

struct PlainVector{CryptoBackendT <: AbstractCryptoBackend, DataT}
    data::DataT
    length::Int
    context::SecureContext{CryptoBackendT}

    function PlainVector(data, length, context::SecureContext{CryptoBackendT}) where CryptoBackendT
        new{CryptoBackendT, typeof(data)}(data, length, context)
    end
end

Base.length(v::PlainVector) = v.length
function Base.show(io::IO, v::PlainVector{CryptoBackendT}) where CryptoBackendT
    print("PlainVector{", backend_name(v), "}(data=<plain>, length=$(v.length))")
end

Base.print(io::IO, plain_vector::PlainVector) = print(io, plain_vector.data)

struct PrivateKey{CryptoBackendT <: AbstractCryptoBackend, KeyT}
    private_key::KeyT
    context::SecureContext{CryptoBackendT}

    function PrivateKey(context::SecureContext{CryptoBackendT}, key) where CryptoBackendT
        new{CryptoBackendT, typeof(key)}(key, context)
    end
end

function Base.show(io::IO, key::PrivateKey{CryptoBackendT}) where CryptoBackendT
    print("PrivateKey{", backend_name(key), "}()")
end

struct PublicKey{CryptoBackendT <: AbstractCryptoBackend, KeyT}
    public_key::KeyT
    context::SecureContext{CryptoBackendT}

    function PublicKey(context::SecureContext{CryptoBackendT}, key) where CryptoBackendT
        new{CryptoBackendT, typeof(key)}(key, context)
    end
end

function Base.show(io::IO, key::PublicKey{CryptoBackendT}) where CryptoBackendT
    print("PublicKey{", backend_name(key), "}()")
end

# Get wrapper name of a potentially parametric type
# Copied from: https://github.com/ClapeyronThermo/Clapeyron.jl/blob/f40c282e2236ff68d91f37c39b5c1e4230ae9ef0/src/utils/core_utils.jl#L17
# Original source: https://github.com/JuliaArrays/ArrayInterface.jl/blob/40d9a87be07ba323cca00f9e59e5285c13f7ee72/src/ArrayInterface.jl#L20
# Note: prefixed by `__` since it is really, really dirty black magic internals we use here!
__parameterless_type(T) = Base.typename(T).wrapper

# Convenience method for getting the human-readable backend name
backend_name(x::Union{SecureContext{T}, SecureVector{T}, PlainVector{T}, PrivateKey{T},
                      PublicKey{T}}) where T = string(__parameterless_type(T))
