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


@testset verbose=true showtiming=true "square_mat_mat_nul" begin
    (context, public_key, private_key) = make_context()

    # SecureArithmetic stores matrices in column order, thus we need to transpose before eval mult
    m1 = collect(transpose([0.25 0.5 0.75;
         1.0 2.0 3.0;
         4.0 5.0 6.0]))
        
    m2 = collect(transpose([6.0 5.0 4.0;
          3.0 2.0 1.0;
          0.75 0.5 0.25]))

    pm1 = PlainMatrix(m1, context)
    pm2 = PlainMatrix(m2, context)


    sm1 = encrypt(pm1, public_key)
    sm2 = encrypt(pm2, public_key)
    
    init_rotation!(context, private_key, (length(m1)), 1:length(m1)...)
    init_multiplication!(context, private_key)

    

    # the result is in row order. This we need to transpose to get the correct matrix in column order
    result = transpose(collect(decrypt(SecureArithmetic.mat_times_mat(sm1, sm2), private_key)))
    @test result ≈   [  3.5625   2.625   1.6875;
                        14.25    10.5     6.75;
                        43.5     33.0    22.5]

end

release_context_memory()
GC.gc()

end # @testset "test_serialization.jl"

end # module
