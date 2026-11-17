# Returns the unique `circshift` amounts that `row_mat_times_mat` applies to the flattened
# arrays, for `sm1` of *padded* shape `(d, l)` and `sm2` of *padded* shape `(d, d)`.
#
# `row_mat_times_mat` flattens both operands and brings them onto a common storage of whole
# `n = d²` blocks before performing any rotation, so every shift below is a 1D `circshift` on
# that storage. The shifts are listed in the same order in which `row_mat_times_mat` performs
# them, and this function must be kept in sync with it.
#
# The resulting set is `{-(d-1), …, d-1} ∪ {0, -d, …, -(d-1)*d}`, i.e. `3d - 2` shifts
# independent of `l`, because every shift of the aggregation step is a multiple of `d` smaller
# than `n`, and the shifts of steps 2 and 3 are a subset of the shifts of the sigma and tau transformations.
function compute_matrix_multiplication_shifts(d::Integer, l::Integer)
    shifts = Int[]
    r = d ÷ l
    p = Int(log2(r)) # since d and l are always padded to a power of two, d÷l is also a power of two

    # Step 1-1: linear transformation sigma on Ā
    for k in -d+1:d-1
        push!(shifts, -k)
    end

    # Step 1-2: linear transformation tau on B
    for k in 0:d-1
        push!(shifts, -(d * k))
    end

    # Steps 2 and 3
    for k in 1:l-1
        push!(shifts, -k, -(k - d), -(d * k))
    end

    # Step 4: aggregation for rectangular matrix multiplication
    for k in 0:p-1
        push!(shifts, -(l * d * 2^k))
    end

    unique(shifts)
end

"""
    init_matrix_multiplication!(context::SecureContext, private_key::PrivateKey,
                                shape_a, shape_b; packed = false)

Generate the rotation keys required to compute the matrix product `a * b` using the
`private_key`, and store them in the given `context`. `shape_a` and `shape_b` are the
*unpadded* shapes of the two operands, i.e. what [`size`](@ref) returns for either layout,
given in the same order as in `a * b`: `shape_b` is either `(d, l)` for a matrix or `(d,)` for
a vector, and `shape_a` has to be `(d, d)`.

Matrix multiplication always runs on the packed layout, so the shifts are those of the
dimensions rounded up to the next power of two. Only the shifts the multiplication algorithm
actually performs are initialized, which are `3d - 2` instead of all `d²` possible shifts of
the internal working vector.

`packed` states whether *both* operands are already in packed layout. With `packed = false`,
the keys of [`init_packing!`](@ref) are generated for both shapes as well, and those of
[`init_unpacking!`](@ref) for the shape of the result, because a product of flat operands has to
convert its operands first and unpacks its result again. Note that
[`init_multiplication!`](@ref) is required for matrix multiplication as well.

See also: [`SecureContext`](@ref), [`PrivateKey`](@ref), [`init_multiplication!`](@ref),
[`init_packing!`](@ref), [`init_unpacking!`](@ref), [`init_rotation!`](@ref)
"""
function init_matrix_multiplication!(context::SecureContext, private_key::PrivateKey,
                                     shape_a, shape_b; packed = false)
    if !(length(shape_b) in (1, 2))
        throw(DimensionMismatch("second operand must be a matrix or a vector, " *
                                "got shape $shape_b"))
    end
    # A vector operand is multiplied as a d×1 matrix
    d = shape_b[1]
    l = length(shape_b) == 1 ? 1 : shape_b[2]
    if d < 1 || l < 1
        throw(DimensionMismatch("second operand must not be empty, got shape $shape_b"))
    end

    # Mirror the dimension checks of `row_mat_times_mat`
    if length(shape_a) != 2 || shape_a[1] != d || shape_a[2] != d
        throw(DimensionMismatch("first operand must be a $d×$d matrix, got shape $shape_a"))
    end

    # `*` converts a flat operand with `as_packed` and unpacks the result again with
    # `as_unpacked`, both of which rotate, so those keys are part of what a product of flat
    # operands needs. The result has the shape of the second operand.
    if !packed
        result_shape = length(shape_b) == 1 ? (Int(d),) : (Int(d), Int(l))
        init_packing!(context, private_key, (Int(d), Int(d)))
        init_packing!(context, private_key, result_shape)
        init_unpacking!(context, private_key, result_shape)
    end

    # The algorithm runs on the padded dimensions, which are powers of two
    d = next_power_of_two(d)
    l = next_power_of_two(l)
    if d % l != 0
        throw(DimensionMismatch("number of rows l=$l does not divide number of columns d=$d"))
    end

    init_rotation!(context, private_key, max(slot_count(context), d * d),
                   compute_matrix_multiplication_shifts(d, l)...)
end

"""
Multiply two d x d matrices in row order

!!! Column order matrices
    If `sm1` and `sm1` encode matrices ``A`` and ``B`` in column order, then `sm1` and `sm2` also encode ``A^T`` and ``B^T`` in row order.
    If  `sm3` encodes  ``(A \\times B)^T`` in row order, then `sm3` also encodes ``A \\times B`` in column order.
    Since  ``(A \\times B)^T = B^T \\times A^T``, we can simply swap the roles of ``A`` and ``B`` to use the algorithm on column-order matrices and get the correct result back, in column order.

Both operands are in packed layout, which is what makes every rotation below a plain,
level-free rotation of the underlying ciphertext; `*` converts a flat operand with `as_packed`
first and unpacks the result again with `as_unpacked`, so that a product keeps the layout of its
operands.

See https://eprint.iacr.org/2018/1041.pdf
"""
function row_mat_times_mat(sm1, sm2)

    # Suppose that we are given an l × d matrix A and a d × d matrix B such that l divides d

    # shape[1] is num rows and shape[2] is num cols
    # but this algorithm receives matrices in the wrong order (B,A instead of A,B), because they are column order, i.e. transposed
    # because they are implicitly transposed, we have to switch num rows and num cols
    # The algorithm runs on the padded dimensions, which are powers of two by construction
    l = sm1.padded_shape[2] # num cols
    d = sm1.padded_shape[1] # num rows

    # The unpadded check comes first, so that the message talks about the shapes the caller
    # passed
    if size(sm2) != (size(sm1, 1), size(sm1, 1))
        throw(DimensionMismatch("sm2 must be a d×d matrix, got $(size(sm2, 1))×$(size(sm2, 2))"))
    end

    if sm2.padded_shape != (d, d)
        throw(DimensionMismatch("sm2 must be a d×d matrix after padding, " *
                                "got $(sm2.padded_shape[1])×$(sm2.padded_shape[2])"))
    end

    # `d` and `l` are powers of two, so `l` divides `d` as soon as it does not exceed it
    if d % l != 0
        throw(DimensionMismatch("number of rows l=$l does not divide number of columns d=$d"))
    end

    shape = size(sm1)
    ctx = sm1.array.context
    n = d * d
    # The storage every `circshift` below is cyclic over: one `n = d²` block, or a whole
    # ciphertext if that is larger. Both are powers of two, so each operand's storage divides
    # it.
    storage = max(slot_count(ctx), n)

    # Construct Ā by repeating A d/l times to fill n = d² slots (Algorithm 3, Jiang et al.)
    # In Section 5 Jiang et al:  "For simplicity, we assume that d is a power-of-two", which
    # the packed layout guarantees by padding every dimension to the next power of two, as
    # openfhe_numpy does, see https://github.com/openfheorg/openfhe-numpy/blob/45857c644bc75321d54f6cdd49cc63f3f948b224/openfhe_numpy/utils/packing.py#L123-L127
    # Ā then needs no repeated doubling at all: `sm1` is tiled with period l*d, so every
    # n = d² block of its storage already holds d/l copies of A. Bringing both operands onto
    # the common storage only repeats whole tiles, which costs no homomorphic operation.
    sm1 = replicate_storage(sm1.array, storage ÷ capacity(sm1))
    sm2 = replicate_storage(sm2.array, storage ÷ capacity(sm2))

    # The masks are tiled with period n just like the data, so they are built from the
    # zero-based index *within* one block
    block_indices = mod.(0:storage-1, n)

    # Step 1-1
    # Compute linear Transformation sigma on Ā
    sm1_sigma = PlainArray(zeros(storage), ctx)

    for k in -d+1:d-1
        if k >= 0
            u_k_sigma = PlainArray([0 <= i-d*k && i-d*k < d-k ? 1 : 0 for i in block_indices], ctx)
        else
            u_k_sigma = PlainArray([-k <= i-(d+k)*d && i-(d+k)*d < d ? 1 : 0 for i in block_indices], ctx)
        end
        # Note that Rot(ct; i) in the paper is a leftshift, i.e. circshift(ct, -i)
        sm1_sigma += circshift(sm1, -(k)) .* u_k_sigma
    end

    # Step 1-2
    # Compute linear Transformation tau on B


    sm2_tau = PlainArray(zeros(storage), ctx)

    for k in 0:d-1
        u_dk_tau = PlainArray([(i - k) / d in 0:d-1 ? 1 : 0 for  i in block_indices], ctx)
        sm2_tau += circshift(sm2, -(d*k)) .* u_dk_tau
    end

    # Steps 2 and 3
    sm3 = sm1_sigma .* sm2_tau
    for k in 1:l-1
        v_k = PlainArray([0 <= (i % d) && (i % d) < (d-k) ? 1 : 0 for  i in block_indices], ctx)
        v_k_d = PlainArray([(d-k) <= (i % d) && (i % d) < d ? 1 : 0 for  i in block_indices], ctx)
        sm1_k = circshift(sm1_sigma, -(k)) .* v_k + circshift(sm1_sigma, -(k-d)) .* v_k_d
        sm2_k = circshift(sm2_tau, -(d*k))
        sm3 += sm1_k .* sm2_k
    end

    # Step 4 (aggregation for rectangular matrix multiplication)
    # Since d and l are powers of two, r = d ÷ l is as well, so the sub-blocks are aggregated
    # by repeated doubling alone. The shifts are cyclic over a whole number of n-blocks, which
    # makes this a full all-reduce: every l*d sub-block ends up with the complete product, so
    # the result is a faithful tile of the padded (d, l) block and can serve as an operand of
    # another multiplication. In the layout of the paper, where the d² block sits in a larger,
    # zero-padded ciphertext, the same rotations pull in zeros instead and do leave partial
    # sums above l*d.
    r = d ÷ l
    p = Int(log2(r))
    for k in 0:p-1
        sm3 += circshift(sm3, -(l*d*2^k))
    end

    return pack_result(sm3, shape, (d, l))
end
