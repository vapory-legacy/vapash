#include <ethash/ethash.hpp>

#include "../../lib/ethash/ethash-internal.hpp"
#include <iostream>

namespace
{
ethash_epoch_context* create_fake_epoch_context(int epoch_number) noexcept
{
    auto context = ethash_create_epoch_context(epoch_number);
    ethash::init_full_dataset(*context);
    uint64_t full_dataset_size = ethash::get_full_dataset_size(context->full_dataset_num_items);
    std::memset(context->full_dataset, 0xa9, full_dataset_size);
    return context;
}

ethash_epoch_context* epoch_context0 = create_fake_epoch_context(0);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* input, size_t size)
{
    if (size == 0)
        return 0;

    const uint8_t test_kind = *input++;
    --size;

    switch (test_kind)
    {
    // Hash using light cache.
    case 0:
    {
        static constexpr size_t required_size = sizeof(ethash::hash256) + sizeof(uint64_t);
        if (size != required_size)
            return 0;

        const auto input_hash = ethash::hash256::from_bytes(input);
        uint64_t nonce = 0;
        std::memcpy(&nonce, input + sizeof(ethash::hash256), sizeof(uint64_t));
        ethash::hash_light(*epoch_context0, input_hash, nonce);
        return 0;
    }

    // Hash using full dataset.
    case 1:
    {
        static constexpr size_t required_size = sizeof(ethash::hash256) + sizeof(uint64_t);
        if (size != required_size)
            return 0;

        const auto input_hash = ethash::hash256::from_bytes(input);
        uint64_t nonce = 0;
        std::memcpy(&nonce, input + sizeof(ethash::hash256), sizeof(uint64_t));
        ethash::hash(*epoch_context0, input_hash, nonce);
        return 0;
    }

    default:
        return 0;
    }
}
