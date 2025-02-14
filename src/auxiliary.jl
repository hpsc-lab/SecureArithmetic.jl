const threads_enabled::Base.RefValue{Bool} = Ref(false)

"""
    enable_multithreading(enabled=true)

Enable multithreaded execution when `enabled` is set to `true`.  
To disable multithreading, use `disable_multithreading`.

This multithreading capability takes place entirely on the Julia side and parallelizes
operations over multiple ciphertexts within a single `SecureArray`. That is, it will
have no effect if only one ciphertext is sufficient to hold all data. Please be aware
that mixing Julia's multithreading with OpenFHE's builtin OpenMP-based multithreading
might cause troubles. Thus if in doubt, set the environment variable `OMP_NUM_THREADS=1`
to avoid potential issues.

Note: By default multithreading is disabled.

See also: [`disable_multithreading`](@ref)
"""
enable_multithreading(enabled=true) = global threads_enabled[] = enabled
"""
    disable_multithreading()

Disable multithreaded execution. To enable multithreading, use `enable_multithreading`.

See also: [`enable_multithreading`](@ref)
"""
disable_multithreading() = enable_multithreading(false)

macro threaded(expr)
    # esc(quote ... end) as suggested in https://github.com/JuliaLang/julia/issues/23221
    return esc(quote
        if Threads.nthreads() == 1 || !threads_enabled[]
            $(expr)
        else
            Threads.@threads $(expr)
        end
    end)
end
