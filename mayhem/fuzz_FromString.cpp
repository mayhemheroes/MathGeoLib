#include <stdint.h>
#include <stdio.h>

#include <fuzzer/FuzzedDataProvider.h>
#include "MathGeoLib.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    OBB::OBB::FromString(str);

    return 0;
}
