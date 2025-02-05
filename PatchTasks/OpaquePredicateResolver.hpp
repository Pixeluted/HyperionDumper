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
    ZydisDecodedOperandImm::ZydisDecodedOperandImmValue_ stackValue;

    std::shared_ptr<DecodedInstruction> moveStackValueToRegisterInstruction;
    ZydisRegister firstCompareRegister;
    ZydisRegister secondCompareRegister;

    std::shared_ptr<DecodedInstruction> compareInstruction;
    ZydisDecodedOperandImm::ZydisDecodedOperandImmValue_ comparedAgainst;

    std::shared_ptr<DecodedInstruction> jumpInstruction;
};

class StackOpaqueAnalyzer final : public PatternAnalyzer<StackOpaqueAnalyzerState> {
    [[nodiscard]] size_t getPatternsCount() const override;
    [[nodiscard]] size_t getFinalProgress() const override;
    [[nodiscard]] const std::pair<int, PatternMatcher> *getPatterns() const override;
    void onPatternMatched() override;
};

void AnalyzeInstructionForOpaquePredicates(const std::shared_ptr<DecodedInstruction> &instruction);
