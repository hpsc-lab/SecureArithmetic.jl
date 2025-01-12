"""
    encrypt(data::Vector{<:Real}, public_key::PublicKey, context::SecureContext)

Encrypt `data` into a [`SecureVector`](@ref) using the `public_key` derived for the given
`context`.

See also: [`SecureVector`](@ref), [`decrypt`](@ref)
"""
function encrypt(data::Vector{<:Real}, public_key::PublicKey, context::SecureContext)
    encrypt_impl(data, public_key, context)
end

"""
    encrypt(plain_vector::PlainVector, public_key::PublicKey)

Encrypt `plain_vector` into a [`SecureVector`](@ref) using the `public_key`.

See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`decrypt`](@ref)
"""
function encrypt(plain_vector::PlainVector, public_key::PublicKey)
    encrypt_impl(plain_vector, public_key)
end

"""
    decrypt!(plain_vector::PlainVector, secure_vector::SecureVector, private_key::PrivateKey)

Decrypt `secure_vector` using the `private_key` and store the result in the given
`plain_text`.

See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`decrypt`](@ref)
"""
function decrypt!(plain_vector::PlainVector, secure_vector::SecureVector,
                  private_key::PrivateKey)
    decrypt_impl!(plain_vector, secure_vector, private_key)
end


"""
    decrypt(secure_vector::SecureVector, private_key::PrivateKey)

Decrypt `secure_vector` using the `private_key` and return the resulting `PlainVector`.

See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`decrypt!`](@ref)
"""
function decrypt(secure_vector::SecureVector, private_key::PrivateKey)
    decrypt_impl(secure_vector, private_key)
end

function encrypt(data::Matrix{<:Real}, public_key::PublicKey, context::SecureContext)
    encrypt_impl(data, public_key, context)
end

function encrypt(plain_matrix::PlainMatrix, public_key::PublicKey)
    encrypt_impl(plain_matrix, public_key)
end

function decrypt!(plain_matrix::PlainMatrix, secure_matrix::SecureMatrix,
                  private_key::PrivateKey)
    decrypt_impl!(plain_matrix, secure_matrix, private_key)
end

function decrypt(secure_matrix::SecureMatrix, private_key::PrivateKey)
    decrypt_impl(secure_matrix, private_key)
end

# function is not unique for data::Vector ot data::Matrix
#=function encrypt(data::Array{<:Real}, public_key::PublicKey, context::SecureContext)
    encrypt_impl(data, public_key, context)
end=#

function encrypt(plain_array::PlainArray, public_key::PublicKey)
    encrypt_impl(plain_array, public_key)
end

function decrypt!(plain_array::PlainArray, secure_array::SecureArray,
                  private_key::PrivateKey)
    decrypt_impl!(plain_array, secure_array, private_key)
end

function decrypt(secure_array::SecureArray, private_key::PrivateKey)
    decrypt_impl(secure_array, private_key)
end

"""
    release_context_memory()

Release all `OpenFHE.CryptoContext`s and keys for multiplication, rotation, bootstrapping and
`OpenFHE.EvalSum` generated in the functions [`init_multiplication!`](@ref),
[`init_rotation!`](@ref), [`init_bootstrapping!`](@ref) and `OpenFHE.EvalSumKeyGen`.

In the source code of OpenFHE C++, all `CryptoContext`s and keys are stored in static objects.
Without using `release_context_memory`, the memory allocated for these contexts and keys will
only be freed after restarting the Julia REPL. It is also advisable to call `GC.gc()` after
a call to `release_context_memory` to clean up all memory on the Julia side.

See also: [`init_multiplication!`](@ref), [`init_rotation!`](@ref), [`init_bootstrapping!`](@ref)
"""
function release_context_memory()
    OpenFHE.ClearEvalMultKeys()
    OpenFHE.ClearEvalSumKeys()
    OpenFHE.ClearEvalAutomorphismKeys()
    OpenFHE.ReleaseAllContexts()
    
    nothing
end
