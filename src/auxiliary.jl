const threads_enabled = Ref(false)

"""
    enable_multithreading(enabled=true)

Enable multithreaded execution when `enabled` is set to `true`.  
To disable multithreading, use `disable_multithreading`.

Note: By default multithreading is disabled

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
