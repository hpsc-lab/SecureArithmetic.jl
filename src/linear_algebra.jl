"""
Multiply two d x d matrices in row order

!!! Column order matrices
    If `sm1` and `sm1` encode matrices ``A`` and ``B`` in column order, then `sm1` and `sm2` also encode ``A^T`` and ``B^T`` in row order.
    If  `sm3` encodes  ``(A \\times B)^T`` in row order, then `sm3` also encodes ``A \\times B`` in column order.
    Since  ``(A \\times B)^T = B^T \\times A^T``, we can simply swap the roles of ``A`` and ``B`` to use the algorithm on column-order matrices and get the correct result back, in column order.

See https://eprint.iacr.org/2018/1041.pdf
"""
function row_mat_times_mat(sm1, sm2)

    # Suppose that we are given an l × d matrix A and a d × d matrix B such that l divides d

    # shape[1] is num rows and shape[2] is num cols
    # but this algorithm receives matrices in the wrong order (B,A instead of A,B), because they are column order, i.e. transposed
    # because they are implicitly transposed, we have to switch num rows and num cols
    l = sm1.shape[2] # num cols
    d = sm1.shape[1] # num rows

    if d % l != 0
        throw(DimensionMismatch("number of rows l=$l does not divide number of columns d=$d"))
    end

    if sm2.shape != (d, d)
        throw(DimensionMismatch("sm2 must be a d×d matrix, got $(sm2.shape[1])×$(sm2.shape[2])"))
    end


    shape = (d, l)
    ctx = sm1.context
    n = d * d

    # Flatten the matrices so that rotations act on flat vectors instead of being 2d rotations
    sm1 = reshape(sm1, (length(sm1),))
    sm2 = reshape(sm2, (length(sm2),))

    # Construct Ā by repeating A d/l times to fill n = d² slots (Algorithm 3, Jiang et al.)
    if l < d
        # when increasing the size using resize, the new elements are not initialized, thus we have to mask 
        sm1 = resize(sm1, n) .* PlainArray([i <= l*d ? 1 : 0 for i in 1:n], ctx)
        r = d ÷ l
        # In Section 5 Jiang et al:  "For simplicity, we assume that d is a power-of-two"
        # openfhe_numpy pads to the next power of two, see https://github.com/openfheorg/openfhe-numpy/blob/45857c644bc75321d54f6cdd49cc63f3f948b224/openfhe_numpy/utils/packing.py#L123-L127
        # This is expensive for already encrypted matrices, see https://github.com/hpsc-lab/SecureArithmetic.jl/pull/119#issuecomment-6467475121
        # Instead, wee adjust the repeated doubling algorithm
        p = floor(Int, log2(r))
        for k in 0:p-1
            sm1 += circshift(sm1, -(l*d*2^k))
        end
        # When r is not a power of two, 2^p < r copies exist after doubling.
        # Mask and shift to fill the remaining r - 2^p copies.
        remaining = r - 2^p
        if remaining > 0
            mask = PlainArray([(remaining + 1) * l * d < i && i <= (2 * remaining + 1) * l * d ? 1 : 0 for i in 1:n], ctx)
            sm1 += circshift(sm1 .* mask, -(remaining * l * d))
        end
    end

    # Step 1-1
    # Compute linear Transformation sigma on Ā
    sm1_sigma = PlainArray(zeros(n), ctx)

    for k in -d+1:d-1
        if k >= 0
            u_k_sigma = PlainArray([0 <= i-d*k && i-d*k < d-k ? 1 : 0 for i in 0:n-1], ctx)
        else
            u_k_sigma = PlainArray([-k <= i-(d+k)*d && i-(d+k)*d < d ? 1 : 0 for i in 0:n-1], ctx)
        end
        # Note that Rot(ct; i) in the paper is a leftshift, i.e. circshift(ct, -i)
        sm1_sigma += circshift(sm1, -(k)) .* u_k_sigma
    end

    # Step 1-2
    # Compute linear Transformation tau on B


    sm2_tau = PlainArray(zeros(n), ctx)

    for k in 0:d-1
        u_dk_tau = PlainArray([(i - k) / d in 0:d-1 ? 1 : 0 for  i in 0:n-1], ctx)
        sm2_tau += circshift(sm2, -(d*k)) .* u_dk_tau
    end

    # Steps 2 and 3
    sm3 = sm1_sigma .* sm2_tau
    for k in 1:l-1
        v_k = PlainArray([0 <= (i % d) && (i % d) < (d-k) ? 1 : 0 for  i in 0:n-1], ctx)
        v_k_d = PlainArray([(d-k) <= (i % d) && (i % d) < d ? 1 : 0 for  i in 0:n-1], ctx)
        sm1_k = circshift(sm1_sigma, -(k)) .* v_k + circshift(sm1_sigma, -(k-d)) .* v_k_d
        sm2_k = circshift(sm2_tau, -(d*k))
        sm3 += sm1_k .* sm2_k
    end

    # Step 4 (aggregation for rectangular matrix multiplication)
    r = d ÷ l
    p = floor(Int, log2(r))
    # In repeated aggregation, when r is not a power of two, we must do the inverse of what we did in repeated doubling:
    # add the last r-2^p entries first, then repeated aggregation p-1 times 
    remaining = r - 2^p
    if remaining > 0
        mask = PlainArray([i > 2^p * l * d ? 1 : 0 for i in 1:n], ctx)
        sm3 += circshift(sm3 .* mask, -(2^p * l * d))
    end
    for k in 0:p-1
        sm3 += circshift(sm3, -(l*d*2^k))
    end

    # Extract the l×d result from the d²-length vector
    if l < d
        sm3 = resize(sm3, l * d)
    end
    return reshape(sm3, shape)
end
