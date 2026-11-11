"""
    init_matrix_multiplication!(context::SecureContext, private_key::PrivateKey,
                                shape_a, shape_b)

Generate all rotation keys required to multiply arrays of shape `shape_a` and `shape_b` using
`*`, and store them in the given `context`. `shape_a` has to be the shape of a matrix, while
`shape_b` may be the shape of either a matrix or a vector.

Note: Matrix multiplication additionally requires multiplication keys, see
[`init_multiplication!`](@ref).

See also: [`SecureContext`](@ref), [`PrivateKey`](@ref), [`init_multiplication!`](@ref),
[`init_rotation!`](@ref)
"""
function init_matrix_multiplication!(context::SecureContext, private_key::PrivateKey,
                                     shape_a, shape_b)
    if length(shape_a) != 2
        throw(DimensionMismatch("first operand must be a matrix, got shape $shape_a"))
    end
    if !(length(shape_b) in (1, 2))
        throw(DimensionMismatch("second operand must be a matrix or a vector, " *
                                "got shape $shape_b"))
    end
    d1, d2 = shape_a
    # A vector operand is multiplied as a d×1 matrix
    d3 = length(shape_b) == 1 ? 1 : shape_b[2]
    if shape_b[1] != d2
        throw(DimensionMismatch("second dimension of first operand ($d2) must match first " *
                                "dimension of second operand ($(shape_b[1]))"))
    end

    # All rotations are applied to flattened (1D) arrays, each with its own length:

    # `extract_columns` rotates the first operand, flattened to length d1 * d2
    if d2 > 1
        init_rotation!(context, private_key, (d1 * d2,), (-d1,))

        # `full_replication` rotates each column of the second operand, i.e. a vector of
        # length d2, by all powers of two in both directions. Only required for an encrypted
        # second operand, but the shapes alone do not tell whether it is encrypted.
        l = floor(Int, log2(d2))
        # For d2 == 2^l, the largest rotation is 2^(l - 1)
        k_max = d2 == 2^l ? l - 1 : l
        init_rotation!(context, private_key, (d2,),
                       ((sign * 2^k,) for k in 0:k_max for sign in (1, -1))...)
    end
    if d3 > 1
        # `extract_columns` rotates the second operand, flattened to length d2 * d3
        init_rotation!(context, private_key, (d2 * d3,), (-d2,))
        # `combine_columns` rotates the resulting columns, resized to length d1 * d3
        init_rotation!(context, private_key, (d1 * d3,), (((j - 1) * d1,) for j in 2:d3)...)
    end

    nothing
end




"""
    extract_columns(mat)

Extract the columns of a column-major `SecureMatrix` or `PlainMatrix` as a list of vectors
using rotation and resize.
"""
function extract_columns(mat)
    d1, d2 = size(mat)
    flat = reshape(mat, (d1*d2))
    columns = []
    for j in 1:d2
        push!(columns, resize(flat, d1))
        if j < d2
            flat = circshift(flat, (-d1,))
        end
    end
    return columns
end

function full_replication(v::PlainArray{B, 1}) where B
    n = length(v)
    data = collect(v)
    [PlainArray(fill(Float64(data[i]), n), v.context) for i in 1:n]
end

"""
    col_mat_times_vec(columns, sv)

Multiply a matrix (given as a list of column vectors) with a vector `sv`.
"""
function col_mat_times_vec(sm, sv)
    n = length(sm)
    v_repl = full_replication(sv)
    w = sm[1] .* v_repl[1]
    for i in 2:n
        w = w + sm[i] .* v_repl[i]
    end
    return w
end

"""
    col_mat_times_vec(mat, vec)

Multiply a `SecureMatrix`/`PlainMatrix` with a `SecureVector`/`PlainVector` by
extracting columns via rotation and resize, then applying the column-list algorithm.
"""
function col_mat_times_vec(mat::Union{SecureArray{B, 2}, PlainArray{B, 2}},
                           vec::Union{SecureArray{B, 1}, PlainArray{B, 1}}) where {B}
    columns = extract_columns(mat)
    col_mat_times_vec(columns, vec)
end

"""
    combine_columns(vectors)

Combine a list of column vectors into a single column-major matrix by resizing,
masking, shifting, and summing.
"""
function combine_columns(vectors)
    d1 = length(vectors[1])
    d2 = length(vectors)
    total_length = d1 * d2
    context = vectors[1].context

    mask = PlainArray(vcat(ones(d1), zeros(total_length - d1)), context)

    result = resize(vectors[1], total_length) .* mask
    for j in 2:d2
        v_resized = resize(vectors[j], total_length) .* mask
        v_shifted = circshift(v_resized, ((j - 1) * d1,))
        result = result + v_shifted
    end

    reshape(result, (d1, d2))
end

"""
    col_mat_times_mat(mat1, mat2)

Multiply two matrices by decomposing into column-wise matrix-vector multiplications.
Columns are extracted from `mat2`, each multiplied by `mat1`, and the results
are combined into a matrix.
"""
function col_mat_times_mat(mat1::Union{SecureArray{B, 2}, PlainArray{B, 2}},
                           mat2::Union{SecureArray{B, 2}, PlainArray{B, 2}}) where {B}
    d1, d2 = size(mat1)
    _, d3 = size(mat2)

    columns_mat2 = extract_columns(mat2)
    result_vectors = [col_mat_times_vec(mat1, col) for col in columns_mat2]
    combine_columns(result_vectors)
end
