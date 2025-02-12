const MULTITHREADING_ENABLED = ScopedValue(false)

with_multithreading(f; enabled=true) = with(f, MULTITHREADING_ENABLED => enabled)
enable_multithreading(enabled=true) = MULTITHREADING_ENABLED[] = enabled
disable_multithreading() = enable_multithreading(false)

macro threaded(expr)
  # esc(quote ... end) as suggested in https://github.com/JuliaLang/julia/issues/23221
  return esc(quote
    if Threads.nthreads() == 1 || !MULTITHREADING_ENABLED[]
      $(expr)
    else
      Threads.@threads $(expr)
    end
  end)
end
