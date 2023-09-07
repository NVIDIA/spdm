#pragma once
#include <cstdint>
#include <variant>

namespace spdmt
{
    // Get version arguments
    struct VerCmd
    {
        uint8_t ver;
    };

    // Get capabilities arguments
    struct CapabCmd
    {
        uint32_t flags;
        uint8_t ctExponent;
    };

    // Negotiate algorithm arguments
    struct NegAlgoCmd
    {
        uint32_t measHashAlgo;
        uint32_t baseAsymAlgo;
        uint32_t baseHashAlgo;
    };

    // Cert command arguments
    struct CertCmd
    {
        uint8_t slot;
        uint16_t offset;
    };

    // Command measurement arguments
    struct MeasCmd
    {
        uint8_t attributes;
        uint8_t blockIndex;
        uint8_t certSlot;
    };

    // Get digest arguments
    struct DigestCmd
    {
    };

    // Commands container
    using cmdv = std::variant<VerCmd, CapabCmd, NegAlgoCmd, CertCmd, MeasCmd, DigestCmd>;
}