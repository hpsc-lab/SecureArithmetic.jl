using SecureArithmetic
using OpenFHE

function simple_array_operations(context)
    public_key, private_key = generate_keys(context)

    init_multiplication!(context, private_key)
    init_bootstrapping!(context, private_key)
    init_array_rotation!(context, private_key, [(1, -1, 1), (0, 1, 0)], (3, 3, 3))
 
    a1 = reshape(Vector(range(1, 27)), (3, 3, 3))
    a2 = reshape(Vector(range(27, 1, step=-1)), (3, 3, 3))

    pa1 = PlainArray(a1, context)
    pa2 = PlainArray(a2, context)

    println("Input array a1: ", pa1)
    println("Input array a2: ", pa2)

    sa1 = encrypt(pa1, public_key)
    sa2 = encrypt(pa2, public_key)

    sa_add = sa1 + sa2

    sa_sub = sa1 - sa2

    sa_scalar = sa1 * 4.0

    sa_mult = sa1 * sa2

    sa_shift1 = circshift(sa1, (0, 1, 0))
    sa_shift2 = circshift(sa1, (1, -1, 1))

    # Perform the bootstrapping operation over a matrix. The goal is to increase the number of
    # levels remaining for HE computation.
    sa_after_bootstrap = bootstrap!(sa1)


    println()
    println("Results of homomorphic computations: ")

    result_sa1 = decrypt(sa1, private_key)
    println("a1 = ", result_sa1)

    result_sa_add = decrypt(sa_add, private_key)
    println("a1 + a2 = ", result_sa_add)

    result_sa_sub = decrypt(sa_sub, private_key)
    println("a1 - a2 = ", result_sa_sub)

    result_sa_scalar = decrypt(sa_scalar, private_key)
    println("4 * a1 = ", result_sa_scalar)

    result_sa_mult = decrypt(sa_mult, private_key)
    println("a1 * a2 = ", result_sa_mult)

    result_sa_shift1 = decrypt(sa_shift1, private_key)
    println("a1 shifted circularly by (0, 1, 0) = ", result_sa_shift1)

    result_sa_shift2 = decrypt(sa_shift2, private_key)
    println("a1 shifted circularly by (1, -1, 1) = ", result_sa_shift2)

    result_after_bootstrap = decrypt(sa_after_bootstrap, private_key)
    println("a1 after bootstrapping \n\t", result_after_bootstrap)
    
    # Clean all `OpenFHE.CryptoContext`s and generated keys.
    release_context_memory()
    GC.gc()
end


################################################################################
println("="^80)
println("Creating OpenFHE context...")

parameters = CCParams{CryptoContextCKKSRNS}()

secret_key_distribution = UNIFORM_TERNARY
SetSecretKeyDist(parameters, secret_key_distribution)

SetSecurityLevel(parameters, HEStd_NotSet)
SetRingDim(parameters, 1 << 5)

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
println("simple_array_operations with an OpenFHE context")
simple_array_operations(context_openfhe)


################################################################################
println("="^80)
println("simple_array_operations with an Unencrypted context")
simple_array_operations(context_unencrypted)
