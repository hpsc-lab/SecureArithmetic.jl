module TestSerialization

using Test
using Serialization
using SecureArithmetic
using OpenFHE

@testset verbose=true showtiming=true "test_serialization.jl" begin

multiplicative_depth = 2
scaling_modulus = 50
batch_size = 8

parameters = CCParams{CryptoContextCKKSRNS}()
SetMultiplicativeDepth(parameters, multiplicative_depth)
SetScalingModSize(parameters, scaling_modulus)
SetBatchSize(parameters, batch_size)

cc = GenCryptoContext(parameters)
Enable(cc, PKE)
Enable(cc, KEYSWITCH)
Enable(cc, LEVELEDSHE)

context = SecureContext(OpenFHEBackend(cc))
public_key, private_key = generate_keys(context)

x1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
pv1 = PlainVector(x1, context)
sv1 = encrypt(pv1, public_key)

x2 = [0.25 0.5; 0.75 1.0; 2.0 3.0; 4.0 5.0]
pm1 = PlainMatrix(x2, context)
sm1 = encrypt(pm1, public_key)

@testset verbose=true showtiming=true "SecureContext" begin
    io = IOBuffer()
    serialize(io, context)
    seekstart(io)
    ctx_restored = deserialize(io)
    @test ctx_restored isa SecureContext
end

@testset verbose=true showtiming=true "PublicKey" begin
    io = IOBuffer()
    serialize(io, public_key)
    seekstart(io)
    pk_restored = deserialize(io)
    @test pk_restored isa SecureArithmetic.PublicKey
end

@testset verbose=true showtiming=true "PrivateKey" begin
    io = IOBuffer()
    serialize(io, private_key)
    seekstart(io)
    sk_restored = deserialize(io)
    @test sk_restored isa SecureArithmetic.PrivateKey
end

@testset verbose=true showtiming=true "SecureVector roundtrip" begin
    io = IOBuffer()
    serialize(io, sv1)
    serialize(io, private_key)
    seekstart(io)
    sv_restored = deserialize(io)
    sk_restored = deserialize(io)

    @test sv_restored isa SecureArray
    @test size(sv_restored) == size(sv1)
    @test capacity(sv_restored) == capacity(sv1)
    @test collect(decrypt(sv_restored, sk_restored)) ≈ collect(decrypt(sv1, private_key))
end

@testset verbose=true showtiming=true "SecureMatrix roundtrip" begin
    io = IOBuffer()
    serialize(io, sm1)
    serialize(io, private_key)
    seekstart(io)
    sm_restored = deserialize(io)
    sk_restored = deserialize(io)

    @test sm_restored isa SecureArray
    @test size(sm_restored) == size(sm1)
    @test capacity(sm_restored) == capacity(sm1)
    @test collect(decrypt(sm_restored, sk_restored)) ≈ collect(decrypt(sm1, private_key))
end

@testset verbose=true showtiming=true "file roundtrip" begin
    mktempdir() do dir
        filepath = joinpath(dir, "data.bin")

        open(filepath, "w") do io
            serialize(io, context)
            serialize(io, public_key)
            serialize(io, private_key)
            serialize(io, sv1)
            serialize(io, sm1)
        end

        open(filepath, "r") do io
            ctx_restored = deserialize(io)
            pk_restored = deserialize(io)
            sk_restored = deserialize(io)
            sv_restored = deserialize(io)
            sm_restored = deserialize(io)

            @test ctx_restored isa SecureContext
            @test pk_restored isa SecureArithmetic.PublicKey
            @test sk_restored isa SecureArithmetic.PrivateKey
            @test sv_restored isa SecureArray
            @test sm_restored isa SecureArray

            @test collect(decrypt(sv_restored, sk_restored)) ≈ collect(decrypt(sv1, private_key))
            @test collect(decrypt(sm_restored, sk_restored)) ≈ collect(decrypt(sm1, private_key))
        end
    end
end

release_context_memory()
GC.gc()

end # @testset "test_serialization.jl"

end # module
