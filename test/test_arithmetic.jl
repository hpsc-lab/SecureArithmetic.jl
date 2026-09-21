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


    return (context, public_key, private_key)
end 

@testset verbose=true showtiming=true "test_arithmetic.jl" begin


@testset verbose=true showtiming=true "circshift" begin
    (context, public_key, private_key) = make_context()
   
    x = [1,2,3,4]
    init_rotation!(context, private_key, 4, 1,2,3,4)
    pv = PlainVector(x, context)
    sv = encrypt(pv, public_key)

    
    @test collect(decrypt(circshift(sv, 1), private_key)) ≈ [4,1,2,3]
    @test collect(decrypt(circshift(sv, 2), private_key)) ≈ [3,4,1,2]
    @test collect(decrypt(circshift(sv, 3), private_key)) ≈ [2,3,4,1]
    @test collect(decrypt(circshift(sv, 4), private_key)) ≈ [1,2,3,4]
    @test collect(decrypt(circshift(sv, 5), private_key)) ≈ [4,1,2,3]
    @test collect(decrypt(circshift(sv, 0), private_key)) ≈ [1,2,3,4]
    @test collect(decrypt(circshift(sv, -1), private_key)) ≈ [2,3,4,1]

    @test collect(decrypt(sv >>> 1, private_key)) ≈ [4,1,2,3]
end

@testset verbose=true showtiming=true "eoshift" begin
    (context, public_key, private_key) = make_context()
   
    x = [1,2,3,4]
    init_rotation!(context, private_key, 4, 1,2,3,4)
    pv = PlainVector(x, context)
    sv = encrypt(pv, public_key)

    
    @test collect(decrypt(eoshift(sv, 1), private_key)) ≈ [0,1,2,3]
    @test collect(decrypt(eoshift(sv, 2), private_key)) ≈ [0,0,1,2]
    @test collect(decrypt(eoshift(sv, 3), private_key)) ≈ [0,0,0,1]
    @test collect(decrypt(eoshift(sv, 4), private_key)) ≈ [0,0,0,0] atol=0.01
    @test collect(decrypt(eoshift(sv, 5), private_key)) ≈ [0,0,0,0] atol=0.01
    @test collect(decrypt(eoshift(sv, 0), private_key)) ≈ [1,2,3,4] 
    @test collect(decrypt(eoshift(sv, -1), private_key)) ≈ [2,3,4,0]

    @test collect(decrypt(sv >> 1, private_key)) ≈ [0,1,2,3]
end

@testset verbose=true showtiming=true "running_sums" begin
    (context, public_key, private_key) = make_context()
    

    v = [1,2,3,4,5]
    init_rotation!(context, private_key, (5), 1,2,3,4,5)

    pv = PlainVector(v, context)
    sv = encrypt(pv, public_key)

    @test collect(decrypt(running_sums(sv), private_key)) ≈ [1,3,6,10,15]
end

@testset verbose=true showtiming=true "total_sums" begin
    (context, public_key, private_key) = make_context()
    
    v = [1,2,3,4,5]
    init_rotation!(context, private_key, (5), 1,2,3,4,5)

    pv = PlainVector(v, context)
    sv = encrypt(pv, public_key)

    @test collect(decrypt(total_sums(sv), private_key)) ≈ [15,15,15,15,15]
end

@testset verbose=true showtiming=true "full_replication" begin
    @testset verbose=true showtiming=true "length 4" begin
        (context, public_key, private_key) = make_context()
        
        v = [1,2,3,4]
        init_rotation!(context, private_key, (4), 1,2,3,4)

        pv = PlainVector(v, context)
        sv = encrypt(pv, public_key)

        @test [collect(decrypt(v, private_key)) for v in full_replication(sv)] ≈ [[1,1,1,1],[2,2,2,2],[3,3,3,3],[4,4,4,4]]

    end
    @testset verbose=true showtiming=true "length 5" begin
        (context, public_key, private_key) = make_context()
        v = [1,2,3,4,5]
        init_rotation!(context, private_key, (5), 1,2,3,4,5)

        pv = PlainVector(v, context)
        sv = encrypt(pv, public_key)

        @test [collect(decrypt(v, private_key)) for v in full_replication(sv)] ≈ [[1,1,1,1,1],[2,2,2,2,2],[3,3,3,3,3],[4,4,4,4,4],[5,5,5,5,5]]
    end
end
release_context_memory()
GC.gc()

end # @testset "test_serialization.jl"

end # module
