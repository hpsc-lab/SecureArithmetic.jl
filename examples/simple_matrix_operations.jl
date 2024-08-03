using SecureArithmetic
using OpenFHE

function simple_matrix_operations(context)
    public_key, private_key = generate_keys(context)

    init_multiplication!(context, private_key)
    init_bootstrapping!(context, private_key)
    init_matrix_rotation!(context, private_key, [(1, -1), (0, 1)], (3, 3))
 
    m1 = [0.25 0.5 0.75;
         1.0 2.0 3.0;
         4.0 5.0 6.0]
        
    m2 = [6.0 5.0 4.0;
          3.0 2.0 1.0;
          0.75 0.5 0.25]

    pm1 = PlainMatrix(m1, context)
    pm2 = PlainMatrix(m2, context)

    println("Input matrix m1: ", pm1)
    println("Input matrix m2: ", pm2)

    sm1 = encrypt(pm1, public_key)
    sm2 = encrypt(pm2, public_key)

    sm_add = sm1 + sm2

    sm_sub = sm1 - sm2

    sm_scalar = sm1 * 4.0

    sm_mult = sm1 * sm2

    sm_shift1 = circshift(sm1, (0, 1))
    sm_shift2 = circshift(sm1, (1, -1))

    # Perform the bootstrapping operation over a matrix. The goal is to increase the number of
    # levels remaining for HE computation.
    sm_after_bootstrap = bootstrap!(sm1)


    println()
    println("Results of homomorphic computations: ")

    result_sm1 = decrypt(sm1, private_key)
    println("m1 = ", result_sm1)

    result_sm_add = decrypt(sm_add, private_key)
    println("m1 + m2 = ", result_sm_add)

    result_sm_sub = decrypt(sm_sub, private_key)
    println("m1 - m2 = ", result_sm_sub)

    result_sm_scalar = decrypt(sm_scalar, private_key)
    println("4 * m1 = ", result_sm_scalar)

    result_sm_mult = decrypt(sm_mult, private_key)
    println("m1 * m2 = ", result_sm_mult)

    result_sm_shift1 = decrypt(sm_shift1, private_key)
    println("m1 shifted circularly by (0, 1) = ", result_sm_shift1)

    result_sm_shift2 = decrypt(sm_shift2, private_key)
    println("m1 shifted circularly by (1, -1) = ", result_sm_shift2)

    result_after_bootstrap = decrypt(sm_after_bootstrap, private_key)
    println("m1 after bootstrapping \n\t", result_after_bootstrap)
    
    # Clean all `OpenFHE.CryptoContext`s and generated keys.
    cleanup()
end


################################################################################
println("="^80)
println("Creating OpenFHE context...")

parameters = CCParams{CryptoContextCKKSRNS}()

secret_key_distribution = UNIFORM_TERNARY
SetSecretKeyDist(parameters, secret_key_distribution)

SetSecurityLevel(parameters, HEStd_NotSet)
SetRingDim(parameters, 1 << 12)

rescale_technique = FLEXIBLEAUTO
dcrt_bits = 59
first_modulus = 60

SetScalingModSize(parameters, dcrt_bits)
SetScalingTechnique(parameters, rescale_technique)
SetFirstModSize(parameters, first_modulus)

level_budget = [4, 4]

levels_available_after_bootstrap = 10
depth = levels_available_after_bootstrap + GetBootstrapDepth(level_budget, secret_key_distribution)
SetMultiplicativeDepth(parameters, depth)

cc = GenCryptoContext(parameters)

Enable(cc, PKE)
Enable(cc, KEYSWITCH)
Enable(cc, LEVELEDSHE)
Enable(cc, ADVANCEDSHE)
Enable(cc, FHE)

ring_dimension = GetRingDimension(cc)
# This is the maximum number of slots that can be used for full packing.
num_slots = div(ring_dimension,  2)
println("CKKS scheme is using ring dimension ", ring_dimension)
println()

EvalBootstrapSetup(cc; level_budget)

context_openfhe = SecureContext(OpenFHEBackend(cc))


################################################################################
println("="^80)
println("Creating unencrypted context...")
println()

context_unencrypted = SecureContext(Unencrypted())


################################################################################
println("="^80)
println("simple_matrix_operations with an OpenFHE context")
simple_matrix_operations(context_openfhe)


################################################################################
println("="^80)
println("simple_matrix_operations with an Unencrypted context")
simple_matrix_operations(context_unencrypted)
