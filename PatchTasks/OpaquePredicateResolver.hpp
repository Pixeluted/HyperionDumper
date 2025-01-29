//
// Created by Pixeluted on 29/01/2025.
//
#pragma once
#include <memory>
#include "../Dissassembler.hpp"

// Structure data for the opaque predicate when a value is moved to stack and then immediately compared with another immediate value
struct StackOpaquePredicateData {
    uint16_t currentProgress = 0;

    std::shared_ptr<DecodedInstruction> moveValueToStackInstruction;
    int64_t stackOffset;
    int64_t stackValue;

    std::shared_ptr<DecodedInstruction> moveStackValueToRegisterInstruction;
    ZydisRegister firstCompareRegister;

    std::shared_ptr<DecodedInstruction> compareInstruction;
    int64_t comparedAgainst;

    std::shared_ptr<DecodedInstruction> jumpInstruction;
};

void AnalyzeInstructionForOpaquePredicates(const std::shared_ptr<DecodedInstruction> &instruction);
