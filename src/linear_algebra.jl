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
        for k in 0:Int(log2(d÷l))-1
            sm1 += circshift(sm1, -(l*d*2^k))
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
    for k in 0:Int(log2(d÷l))-1
        sm3 += circshift(sm3, -(l*d*2^k))
    end

    # Extract the l×d result from the d²-length vector
    if l < d
        sm3 = resize(sm3, l * d)
    end
    return reshape(sm3, shape)
end
