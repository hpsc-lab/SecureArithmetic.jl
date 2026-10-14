module TestLinearAlgebra

using Test
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

@testset verbose=true showtiming=true "test_linear_algebra.jl" begin


@testset verbose=true showtiming=true "full_replication" begin
    @testset verbose=true showtiming=true "length 4" begin
        (context, public_key, private_key) = make_context()
        
        m = [[1,0,0,0], [0,1,0,0], [0,0,1,0], [0,0,0,1]] # The 4x4 identity
        v = [1,2,3,4]
        
        init_rotation!(context, private_key, (4), 1,2,3,4)

        mv = PlainVector(v, context)
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

@testset verbose=true showtiming=true "col_mat_times_vec" begin
    (context, public_key, private_key) = make_context()

    m = [[2,0,0,0], [0,1,0,0], [0,0,1,0], [0,0,0,2]]

    v = [1,2,3,4]
    init_rotation!(context, private_key, (5), 1,2,3,4,5)
    init_multiplication!(context, private_key)

    pv = PlainVector(v, context)
    sv = encrypt(pv, public_key)

    sm = [encrypt(PlainVector(row, context), public_key) for row in m]

    result = collect(decrypt(SecureArithmetic.col_mat_times_vec(sm, sv), private_key))
    @test result ≈ [2,2,3,8]
end

release_context_memory()
GC.gc()

end # @testset "test_serialization.jl"

end # module
