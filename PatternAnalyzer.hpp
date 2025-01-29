//
// Created by Pixeluted on 29/01/2025.
//
#pragma once
#include <type_traits>
#include <spdlog/spdlog.h>

#include "Dissassembler.hpp"

struct BaseAnalyzerState {
    int currentProgress = 0;
    virtual ~BaseAnalyzerState() = default;
};

template<typename T>
concept DerivedFromBaseAnalyzerState = std::is_base_of_v<BaseAnalyzerState, T>;

template<typename StateType>
    requires DerivedFromBaseAnalyzerState<StateType>
class PatternAnalyzer {
public:
    StateType currentAnalyzerState;
    using PatternMatcher = bool(*)(const std::shared_ptr<DecodedInstruction>& instruction, StateType& analyzerState);
protected:
    virtual const std::pair<int, PatternMatcher>* getPatterns() const = 0;
    [[nodiscard]] virtual size_t getPatternsCount() const = 0; // This must return the last patter matcher state number
    [[nodiscard]] virtual size_t getFinalProgress() const = 0;
    virtual void onPatternMatched() = 0;

public:
    PatternAnalyzer(): currentAnalyzerState(StateType{}) {}
    virtual ~PatternAnalyzer() = default;

    void analyzeInstruction(const std::shared_ptr<DecodedInstruction>& instruction, const bool isRecheck = false) {
        bool hasMatched = false;
        const auto* allPatterns = getPatterns();
        const auto patternsCount = getPatternsCount() + 1;

        for (size_t i = 0; i < patternsCount; i++) {
            const auto& [progress, matcher] = allPatterns[i];
            if (progress == currentAnalyzerState.currentProgress && matcher(instruction, currentAnalyzerState)) {
                ++currentAnalyzerState.currentProgress;
                hasMatched = true;
                break;
            }
        }

        if (!hasMatched) {
            currentAnalyzerState.currentProgress = 0;
            if (!isRecheck) {
                analyzeInstruction(instruction, true);
            }
            return;
        }

        if (getFinalProgress() == currentAnalyzerState.currentProgress) {
            onPatternMatched();
            currentAnalyzerState.currentProgress = 0;
        }
    }
};
