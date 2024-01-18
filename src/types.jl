abstract type AbstractCryptoBackend end

struct SecureContext{CryptoBackendT <: AbstractCryptoBackend}
    backend::CryptoBackendT
end

struct SecureVector{CryptoBackendT <: AbstractCryptoBackend, CiphertextT}
    ciphertext::CiphertextT
    context::SecureContext{CryptoBackendT}

    function SecureVector(ciphertext, context::SecureContext{CryptoBackendT}) where CryptoBackendT
        new{CryptoBackendT, typeof(ciphertext)}(ciphertext, context)
    end
end

struct PlainVector{CryptoBackendT <: AbstractCryptoBackend, PlaintextT}
    plaintext::PlaintextT
    context::SecureContext{CryptoBackendT}

    function PlainVector(plaintext, context::SecureContext{CryptoBackendT}) where CryptoBackendT
        new{CryptoBackendT, typeof(plaintext)}(plaintext, context)
    end
end

Base.print(io::IO, plain_vector::PlainVector) = print(io, plain_vector.plaintext)

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
