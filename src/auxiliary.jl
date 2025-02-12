threads_enabled = false

function enable_multithreading(enabled=true)
    global threads_enabled = enabled
end
disable_multithreading() = enable_multithreading(false)

macro threaded(expr)
    # esc(quote ... end) as suggested in https://github.com/JuliaLang/julia/issues/23221
    return esc(quote
        if Threads.nthreads() == 1 || !threads_enabled
            $(expr)
        else
            Threads.@threads $(expr)
        end
    end)
end
