"""
Multiply an encrypted n x n matrix with an encrypted n x 1 vector
"""
function col_mat_times_vec(sm, sv)
    n = length(sm)
    w = PlainArray(zeros(n), sv.context)
    for i in 1:n
        v_repl = full_replication(sv)
        w += sm[i] * v_repl[i]
    end
    return w
end

