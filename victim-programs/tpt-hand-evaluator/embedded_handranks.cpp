#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" {
    extern const uint8_t _binary_HandRanks_dat_start[];
    extern const uint8_t _binary_HandRanks_dat_end[];
}

static const size_t HR_BYTE_SIZE = &_binary_HandRanks_dat_end[0] - &_binary_HandRanks_dat_start[0];

const int32_t* HR_embedded = reinterpret_cast<const int32_t*>(&_binary_HandRanks_dat_start[0]);
