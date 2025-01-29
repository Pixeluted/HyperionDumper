//
// Created by Pixeluted on 29/01/2025.
//
#pragma once
#include <memory>
#include "../Dissassembler.hpp"
#include "../PatternAnalyzer.hpp"

// Structure data for the opaque predicate when a value is moved to stack and then immediately compared with another immediate value
struct StackOpaqueAnalyzerState : BaseAnalyzerState {
    int currentProgress = 0;

    std::shared_ptr<DecodedInstruction> moveValueToStackInstruction;
    int64_t stackOffset;
    uint64_t stackValue;

    std::shared_ptr<DecodedInstruction> moveStackValueToRegisterInstruction;
    ZydisRegister firstCompareRegister;

    std::shared_ptr<DecodedInstruction> compareInstruction;
    uint64_t comparedAgainst;

    std::shared_ptr<DecodedInstruction> jumpInstruction;
};

class StackOpaqueAnalyzer : public PatternAnalyzer<StackOpaqueAnalyzerState> {
    [[nodiscard]] size_t getPatternsCount() const override;
    [[nodiscard]] size_t getFinalProgress() const override;
    [[nodiscard]] const std::pair<int, PatternMatcher> *getPatterns() const override;
    void onPatternMatched() override;
};

void AnalyzeInstructionForOpaquePredicates(const std::shared_ptr<DecodedInstruction> &instruction);
