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


@testset verbose=true showtiming=true "square_col_mat_mat_mul" begin
    (context, public_key, private_key) = make_context()

    m1 = collect([0.25 0.5 0.75;
         1.0 2.0 3.0;
         4.0 5.0 6.0])
        
    m2 = collect([6.0 5.0 4.0;
          3.0 2.0 1.0;
          0.75 0.5 0.25])

    pm1 = PlainMatrix(m1, context)
    pm2 = PlainMatrix(m2, context)


    sm1 = encrypt(pm1, public_key)
    sm2 = encrypt(pm2, public_key)
    
    init_rotation!(context, private_key, (length(m1)), 1:length(m1)...)
    init_multiplication!(context, private_key)

    

    expected = [  3.5625   2.625   1.6875;
                        14.25    10.5     6.75;
                        43.5     33.0    22.5]

    @test collect(decrypt(sm1 * sm2, private_key)) ≈ expected   
    @test collect(decrypt(sm1 * pm2, private_key)) ≈ expected   
    @test collect(decrypt(pm1 * sm2, private_key)) ≈ expected
    @test collect(pm1 * pm2) ≈ expected
end

@testset verbose=true showtiming=true "rect_col_mat_mat_mul" begin
    (context, public_key, private_key) = make_context()

    m1 = collect([0.25 0.5 0.75 1.0;
         1.0 2.0 3.0 4.0;
         4.0 5.0 6.0 7.0;
         2.0 4.0 8.0 16.0;
         ])
        
    m2 = collect([6.0 5.0;
          3.0 2.0;
          0.75 0.5
          2.0 4.0
          ])

    pm1 = PlainMatrix(m1, context)
    pm2 = PlainMatrix(m2, context)


    sm1 = encrypt(pm1, public_key)
    sm2 = encrypt(pm2, public_key)
    
    init_rotation!(context, private_key, (length(m1)), 1:length(m1)...)
    init_multiplication!(context, private_key)

    

    expected = [  
        5.5625   6.625
        22.25    26.5
        57.5     61.0
        62.0     86.0
    ]

    @test collect(decrypt(sm1 * sm2, private_key)) ≈ expected   
    @test collect(decrypt(sm1 * pm2, private_key)) ≈ expected   
    @test collect(decrypt(pm1 * sm2, private_key)) ≈ expected
    @test collect(pm1 * pm2) ≈ expected
end

@testset verbose=true showtiming=true "mat_times_vec" begin
    (context, public_key, private_key) = make_context()

    m = collect([0.25 0.5 0.75 1.0;
         1.0 2.0 3.0 4.0;
         4.0 5.0 6.0 7.0;
         2.0 4.0 8.0 16.0;
         ])
        
    v = [6.0, 3.0, 0.75, 2.0]

    pm = PlainMatrix(m, context)
    pv = PlainVector(v, context)


    sm = encrypt(pm, public_key)
    sv = encrypt(pv, public_key)
    
    init_rotation!(context, private_key, (length(m)), 1:length(m)...)
    init_multiplication!(context, private_key)

    

    expected = [  
        5.5625
        22.25
        57.5
        62.0
    ]

    @test collect(decrypt(sm * sv, private_key)) ≈ expected   
    @test collect(decrypt(sm * pv, private_key)) ≈ expected   
    @test collect(decrypt(pm * sv, private_key)) ≈ expected
    @test collect(pm * pv) ≈ expected
end


release_context_memory()
GC.gc()

end # @testset "test_serialization.jl"

end # module
