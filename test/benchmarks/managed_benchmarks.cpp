// vapash: C/C++ implementation of Vapash, the Vapory Proof of Work algorithm.
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0. See the LICENSE file.

#include <vapash/vapash.hpp>

#include <benchmark/benchmark.h>

static void get_epoch_context(benchmark::State& state)
{
    const auto e = static_cast<int>(state.range(0));

    vapash::get_global_epoch_context(0);

    for (auto _ : state)
    {
        auto& ctx = vapash::get_global_epoch_context(e);
        benchmark::DoNotOptimize(&ctx);
    }
}
BENCHMARK(get_epoch_context)->Arg(0)->ThreadRange(1, 8);
