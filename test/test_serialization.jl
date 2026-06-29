module TestSerialization

using Test
using Serialization
using SecureArithmetic
using OpenFHE

function make_context()
    level_budget = [4, 4]
    levels_after_bootstrap = 10
    depth = levels_after_bootstrap + GetBootstrapDepth(level_budget, UNIFORM_TERNARY)

    parameters = CCParams{CryptoContextCKKSRNS}()
    SetSecretKeyDist(parameters, UNIFORM_TERNARY)
    SetSecurityLevel(parameters, HEStd_NotSet)
    SetRingDim(parameters, 1 << 12)
    SetScalingModSize(parameters, 59)
    SetScalingTechnique(parameters, FLEXIBLEAUTO)
    SetFirstModSize(parameters, 60)
    SetMultiplicativeDepth(parameters, depth)

    cc = GenCryptoContext(parameters)
    Enable(cc, PKE)
    Enable(cc, KEYSWITCH)
    Enable(cc, LEVELEDSHE)
    Enable(cc, ADVANCEDSHE)
    Enable(cc, FHE)

    EvalBootstrapSetup(cc; level_budget)

    context = SecureContext(OpenFHEBackend(cc))
    public_key, private_key = generate_keys(context)

    x1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
    pv1 = PlainVector(x1, context)
    sv1 = encrypt(pv1, public_key)

    x2 = [0.25 0.5; 0.75 1.0; 2.0 3.0; 4.0 5.0]
    pm1 = PlainMatrix(x2, context)
    sm1 = encrypt(pm1, public_key)
    return (context, public_key, private_key, x1, sv1, x2, sm1)
end 

@testset verbose=true showtiming=true "test_serialization.jl" begin

@testset verbose=true showtiming=true "SecureContext" begin
    (context, public_key, private_key, x1, sv1, x2, sm1) = make_context()
    io = IOBuffer()
    serialize(io, context)
    seekstart(io)
    ctx_restored = deserialize(io)
    @test ctx_restored isa SecureContext
end

@testset verbose=true showtiming=true "PublicKey" begin
    (context, public_key, private_key, x1, sv1, x2, sm1) = make_context()
    io = IOBuffer()
    serialize(io, public_key)
    seekstart(io)
    pk_restored = deserialize(io)
    @test pk_restored isa SecureArithmetic.PublicKey
end

@testset verbose=true showtiming=true "PrivateKey" begin
    (context, public_key, private_key, x1, sv1, x2, sm1) = make_context()
    io = IOBuffer()
    serialize(io, private_key)
    seekstart(io)
    sk_restored = deserialize(io)
    @test sk_restored isa SecureArithmetic.PrivateKey
end

@testset verbose=true showtiming=true "SecureVector roundtrip" begin
    (context, public_key, private_key, x1, sv1, x2, sm1) = make_context()
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
    (context, public_key, private_key, x1, sv1, x2, sm1) = make_context()
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
    (context, public_key, private_key, x1, sv1, x2, sm1) = make_context()
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

@testset verbose=true showtiming=true "SecureContext eval key roundtrip" begin
    (context, public_key, private_key, x1, sv1, x2, sm1) = make_context()
    init_multiplication!(context, private_key)

    io = IOBuffer()
    serialize(io, private_key)
    serialize(io, sv1)
    seekstart(io)

    # Clear eval keys from the global cache so they only exist in the serialized data
    ClearEvalMultKeys()
    ClearEvalAutomorphismKeys()
    ReleaseAllContexts() # simulate separate processes by releaseing all contexts before deserialization

    # Deserialize — eval mult keys should be restored from the serialized context
    # No need to deserialize the context explicitly. 
    # Each serialized SecureArithmetic object holds a serialized reference to its context 
    sk_restored = deserialize(io)
    sv_restored = deserialize(io)

    # Multiplication requires eval mult keys — this proves they survived the roundtrip
    sv_mult = sv_restored * sv_restored
    result = collect(decrypt(sv_mult, sk_restored))
    @test result ≈ x1 .^ 2
end

@testset verbose=true showtiming=true "SecureContext bootstrap key roundtrip" begin
    (context, public_key, private_key, x1, sv1, x2, sm1) = make_context()
    init_multiplication!(context, private_key)
    init_bootstrapping!(context, private_key)

    io = IOBuffer()
    serialize(io, private_key)
    serialize(io, sv1)
    seekstart(io)

    ClearEvalMultKeys()
    ClearEvalAutomorphismKeys()
    ReleaseAllContexts()

    sk_restored = deserialize(io)
    sv_restored = deserialize(io)

    sv_bootstrapped = bootstrap!(sv_restored)
    result = collect(decrypt(sv_bootstrapped, sk_restored))
    @test result ≈ x1
end

release_context_memory()
GC.gc()

end # @testset "test_serialization.jl"

end # module
