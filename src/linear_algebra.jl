"""
Multiply two d x d matrices


See https://eprint.iacr.org/2018/1041.pdf

"""
function mat_times_mat(A, B)
    
n = length(A)
d = Int(sqrt(n))
shape = A.shape
ctx = A.context

# Flatten the matrices so that rotations act on flat vectors instead of being 2d rotations
A = reshape(A, (n))
B = reshape(B, (n))

# Step 1-1 
# Compute linear Transformation sigma on A


A_0 = PlainArray(zeros(n), ctx)

for k in -d+1:d-1
    if k >= 0
        u_k_sigma = PlainArray([0 <= l-d*k && l-d*k < d-k ? 1 : 0 for l in 0:n-1], ctx)
    else 
        u_k_sigma = PlainArray([-k <= l-(d+k)*d && l-(d+k)*d < d ? 1 : 0 for l in 0:n-1], ctx)
    end
    # Note that Rot(ct; l) in the paper is a leftshift, i.e. circshift(ct, -l)
    A_0 += circshift(A, -(k)) * u_k_sigma
end

# Step 1-2
# Compute linear Transformation tau on B


B_0 = PlainArray(zeros(n), ctx)

for k in 0:d-1
    u_dk_tau = PlainArray([(l - k) / d in 0:d-1 ? 1 : 0 for  l in 0:n-1], ctx)
    B_0 += circshift(B, -(d*k)) * u_dk_tau
end

# Step 2 and 3
AB = A_0 * B_0
for k in 1:d-1
    v_k = PlainArray([0 <= (l % d) && (l % d) < (d-k) ? 1 : 0 for  l in 0:n-1], ctx)
    v_k_d = PlainArray([(d-k) <= (l % d) && (l % d) < d ? 1 : 0 for  l in 0:n-1], ctx)
    A_k = circshift(A_0, -(k)) * v_k + circshift(A_0, -(k-d)) * v_k_d
    B_k = circshift(B_0, -(d*k))
    AB += A_k * B_k
end
return reshape(AB, shape) 
end
