"""
Multiply two d x d matrices in row order

!!! Column order matrices
    If `sm1` and `sm1` encode matrices ``A`` and ``B`` in column order, then `sm1` and `sm2` also encode ``A^T`` and ``B^T`` in row order.
    If  `sm3` encodes  ``(A \\times B)^T`` in row order, then `sm3` also encodes ``A \\times B`` in column order. 
    Since  ``(A \\times B)^T = B^T \\times A^T``, we can simply swap the roles of ``A`` and ``B`` to use the algorithm on column-order matrices and get the correct result back, in column order. 

See https://eprint.iacr.org/2018/1041.pdf
"""
function row_mat_times_mat(sm1, sm2) 
    n = length(sm1)
    d = Int(sqrt(n))
    shape = sm1.shape
    ctx = sm1.context

    # Flatten the matrices so that rotations act on flat vectors instead of being 2d rotations
    sm1 = reshape(sm1, (n))
    sm2 = reshape(sm2, (n))

    # Step 1-1 
    # Compute linear Transformation sigma on A


    sm1_sigma = PlainArray(zeros(n), ctx)

    for k in -d+1:d-1
        if k >= 0
            u_k_sigma = PlainArray([0 <= l-d*k && l-d*k < d-k ? 1 : 0 for l in 0:n-1], ctx)
        else 
            u_k_sigma = PlainArray([-k <= l-(d+k)*d && l-(d+k)*d < d ? 1 : 0 for l in 0:n-1], ctx)
        end
        # Note that Rot(ct; l) in the paper is a leftshift, i.e. circshift(ct, -l)
        sm1_sigma += circshift(sm1, -(k)) .* u_k_sigma
    end

    # Step 1-2
    # Compute linear Transformation tau on B


    sm2_tau = PlainArray(zeros(n), ctx)

    for k in 0:d-1
        u_dk_tau = PlainArray([(l - k) / d in 0:d-1 ? 1 : 0 for  l in 0:n-1], ctx)
        sm2_tau += circshift(sm2, -(d*k)) .* u_dk_tau
    end

    # Step 2 and 3
    sm3 = sm1_sigma .* sm2_tau
    for k in 1:d-1
        v_k = PlainArray([0 <= (l % d) && (l % d) < (d-k) ? 1 : 0 for  l in 0:n-1], ctx)
        v_k_d = PlainArray([(d-k) <= (l % d) && (l % d) < d ? 1 : 0 for  l in 0:n-1], ctx)
        sm1_k = circshift(sm1_sigma, -(k)) * v_k + circshift(sm1_sigma, -(k-d)) * v_k_d
        sm2_k = circshift(sm2_tau, -(d*k))
        sm3 += sm1_k .* sm2_k
    end
    return reshape(sm3, shape) 
end
