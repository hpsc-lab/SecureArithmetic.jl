using SecureArithmetic
using OpenFHE

# Note: this is a significantly extended version of the original
# `simple_ckks_bootstrapping.jl` example in OpenFHE.jl, usage of matrices was added.
function simple_real_numbers(context)
    public_key, private_key = generate_keys(context)

    init_multiplication!(context, private_key)
    init_rotation!(context, private_key, [-1, 2])


    x1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
    x2 = [5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]

    pv1 = PlainVector(x1, context)
    pv2 = PlainVector(x2, context)

    println("Computations over vectors")
    println("Input vector x1: ", pv1)
    println("Input vector x2: ", pv2)

    sv1 = encrypt(pv1, public_key)
    sv2 = encrypt(pv2, public_key)

    sv_add = sv1 + sv2

    sv_sub = sv1 - sv2

    sv_scalar = sv1 * 4.0

    sv_mult = sv1 * sv2

    sv_shift1 = circshift(sv1, -1)
    sv_shift2 = circshift(sv1, 2)


    println()
    println("Results of homomorphic computations: ")

    result_sv1 = decrypt(sv1, private_key)
    println("x1 = ", result_sv1)

    result_sv_add = decrypt(sv_add, private_key)
    println("x1 + x2 = ", result_sv_add)

    result_sv_sub = decrypt(sv_sub, private_key)
    println("x1 - x2 = ", result_sv_sub)

    result_sv_scalar = decrypt(sv_scalar, private_key)
    println("4 * x1 = ", result_sv_scalar)

    result_sv_mult = decrypt(sv_mult, private_key)
    println("x1 * x2 = ", result_sv_mult)

    result_sv_shift1 = decrypt(sv_shift1, private_key)
    println("x1 shifted circularly by -1 = ", result_sv_shift1)

    result_sv_shift2 = decrypt(sv_shift2, private_key)
    println("x1 shifted circularly by 2 = ", result_sv_shift2)

    ################################################################################
    init_matrix_rotation!(context, private_key, [(1, 0), (0, 1)], (2, 3))

    m1 = [0.25 0.5 0.75; 1.0 2.0 3.0]
    m2 = [3.0 2.0 1.0; 0.75 0.5 0.25]

    pm1 = PlainMatrix(m1, context)
    pm2 = PlainMatrix(m2, context)
    
    println()
    println("Computations over matrices")
    println("Input matrix m1: ", pm1)
    println("Input matrix m2: ", pm2)

    sm1 = encrypt(pm1, public_key)
    sm2 = encrypt(pm2, public_key)

    sm_add = sm1 + sm2

    sm_sub = sm1 - sm2

    sm_scalar = sm1 * 4.0

    sm_mult = sm1 * sm2

    sm_shift1 = circshift(sm1, (0, 1))
    sm_shift2 = circshift(sm1, (1, 0))


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
    println("m1 shifted circularly by (1, 0) = ", result_sm_shift2)
end


################################################################################
println("="^80)
println("Creating OpenFHE context...")

multiplicative_depth = 1
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
println("CKKS scheme is using ring dimension ", GetRingDimension(cc))
println()

context_openfhe = SecureContext(OpenFHEBackend(cc))


################################################################################
println("="^80)
println("Creating unencrypted context...")
println()

context_unencrypted = SecureContext(Unencrypted())


################################################################################
println("="^80)
println("simple_real_numbers with an OpenFHE context")
simple_real_numbers(context_openfhe)
println()


################################################################################
println("="^80)
println("simple_real_numbers with an Unencrypted context")
simple_real_numbers(context_unencrypted)

