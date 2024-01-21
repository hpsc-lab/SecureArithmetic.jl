abstract type AbstractCryptoBackend end

struct SecureContext{CryptoBackendT <: AbstractCryptoBackend}
    backend::CryptoBackendT
end

struct SecureVector{CryptoBackendT <: AbstractCryptoBackend, DataT}
    data::DataT
    context::SecureContext{CryptoBackendT}

    function SecureVector(data, context::SecureContext{CryptoBackendT}) where CryptoBackendT
        new{CryptoBackendT, typeof(data)}(data, context)
    end
end

struct PlainVector{CryptoBackendT <: AbstractCryptoBackend, DataT}
    data::DataT
    context::SecureContext{CryptoBackendT}

    function PlainVector(data, context::SecureContext{CryptoBackendT}) where CryptoBackendT
        new{CryptoBackendT, typeof(data)}(data, context)
    end
end

Base.print(io::IO, plain_vector::PlainVector) = print(io, plain_vector.data)

struct PrivateKey{CryptoBackendT <: AbstractCryptoBackend, KeyT}
    private_key::KeyT
    context::SecureContext{CryptoBackendT}

    function PrivateKey(context::SecureContext{CryptoBackendT}, key) where CryptoBackendT
        new{CryptoBackendT, typeof(key)}(key, context)
    end
end

struct PublicKey{CryptoBackendT <: AbstractCryptoBackend, KeyT}
    public_key::KeyT
    context::SecureContext{CryptoBackendT}

    function PublicKey(context::SecureContext{CryptoBackendT}, key) where CryptoBackendT
        new{CryptoBackendT, typeof(key)}(key, context)
    end
end
