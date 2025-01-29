//
// Created by Pixeluted on 29/01/2025.
//

#include "OpaquePredicateResolver.hpp"

#include <spdlog/spdlog.h>

bool IsMoveImmediateValueToStackInstruction(const std::shared_ptr<DecodedInstruction> &instruction) {
    return instruction->instruction->mnemonic == ZYDIS_MNEMONIC_MOV &&
           instruction->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
           instruction->operands[0].mem.base == ZYDIS_REGISTER_RSP &&
           instruction->operands[0].mem.disp.value != 0 &&
           instruction->operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
}

bool IsMoveStackValueToRegisterInstruction(const std::shared_ptr<DecodedInstruction> &instruction,
                                           const StackOpaqueAnalyzerState &analyzerState) {
    return instruction->instruction->mnemonic == ZYDIS_MNEMONIC_MOV &&
           instruction->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
           instruction->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
           instruction->operands[1].mem.base == ZYDIS_REGISTER_RSP &&
           instruction->operands[1].mem.disp.value == analyzerState.stackOffset;
}

bool IsCompareValuesInstruction(const std::shared_ptr<DecodedInstruction> &instruction,
                                const StackOpaqueAnalyzerState &analyzerState) {
    return instruction->instruction->mnemonic == ZYDIS_MNEMONIC_CMP &&
           instruction->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
           instruction->operands[0].reg.value == analyzerState.firstCompareRegister &&
           instruction->operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
}

bool IsJumpInstruction(const std::shared_ptr<DecodedInstruction> &instruction) {
    switch (instruction->instruction->mnemonic) {
        case ZYDIS_MNEMONIC_JNZ:
        case ZYDIS_MNEMONIC_JZ:
        case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JNB:
        case ZYDIS_MNEMONIC_JB:
        case ZYDIS_MNEMONIC_JBE:
            return true;
        default:
            return false;
    }
}

bool WillStackOpaquePredicateJump(const StackOpaqueAnalyzerState &analyzerState) {
    switch (analyzerState.jumpInstruction->instruction->mnemonic) {
        case ZYDIS_MNEMONIC_JZ:
            if (analyzerState.compareInstruction->instruction->mnemonic == ZYDIS_MNEMONIC_TEST) {
                if (analyzerState.comparedAgainst == 1) {
                    return (analyzerState.stackValue & 1) == 0;
                }
            }
            return analyzerState.stackValue == analyzerState.comparedAgainst;
        case ZYDIS_MNEMONIC_JNZ:
            return analyzerState.stackValue != analyzerState.comparedAgainst;
        case ZYDIS_MNEMONIC_JNBE:
            return analyzerState.stackValue > analyzerState.comparedAgainst;
        case ZYDIS_MNEMONIC_JNB:
            return analyzerState.stackValue >= analyzerState.comparedAgainst;
        case ZYDIS_MNEMONIC_JB:
            return analyzerState.stackValue < analyzerState.comparedAgainst;
        case ZYDIS_MNEMONIC_JBE:
            return analyzerState.stackValue <= analyzerState.comparedAgainst;
        default:
            return false;
    }
}

void ResolveStackOpaquePredicate(const StackOpaqueAnalyzerState &analyzerState) {
    const auto originalLength = analyzerState.jumpInstruction->instruction->length;

    const auto willJump = WillStackOpaquePredicateJump(analyzerState);
    if (willJump) {
        const auto targetAddress = analyzerState.jumpInstruction->operands[0];
        const auto buffer = analyzerState.jumpInstruction->dumpInfo->DumpInfo->ImageBuffer.get() +
                            analyzerState.jumpInstruction->offsetFromDllBase;

        if (targetAddress.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if (targetAddress.size == 8) {
                memset(buffer, 0x90, originalLength);
                const uint8_t newJump[] = {
                    0xEB, static_cast<uint8_t>(targetAddress.imm.value.u)
                };
                memcpy(buffer, newJump, sizeof(newJump));

                spdlog::info("Resolved opaque predicate at 0x{0:x} with short relative jump patch!",
                             analyzerState.jumpInstruction->offsetFromDllBase);
            } else if (targetAddress.size == 32) {
                memset(buffer, 0x90, originalLength);
                const uint8_t newJump[] = {
                    0xE9,
                    static_cast<uint8_t>(targetAddress.imm.value.u & 0xFF),
                    static_cast<uint8_t>((targetAddress.imm.value.u >> 8) & 0xFF),
                    static_cast<uint8_t>((targetAddress.imm.value.u >> 16) & 0xFF),
                    static_cast<uint8_t>((targetAddress.imm.value.u >> 24) & 0xFF)
                };
                memcpy(buffer, newJump, sizeof(newJump));

                spdlog::info("Resolved opaque predicate at 0x{0:x} with near relative jump patch!",
                             analyzerState.jumpInstruction->offsetFromDllBase);
            } else if (targetAddress.size == 64) {
                memset(buffer, 0x90, originalLength);
                const uint8_t newJump[] = {
                    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                    static_cast<uint8_t>(targetAddress.imm.value.u & 0xFF),
                    static_cast<uint8_t>((targetAddress.imm.value.u >> 8) & 0xFF),
                    static_cast<uint8_t>((targetAddress.imm.value.u >> 16) & 0xFF),
                    static_cast<uint8_t>((targetAddress.imm.value.u >> 24) & 0xFF),
                    static_cast<uint8_t>((targetAddress.imm.value.u >> 32) & 0xFF),
                    static_cast<uint8_t>((targetAddress.imm.value.u >> 40) & 0xFF),
                    static_cast<uint8_t>((targetAddress.imm.value.u >> 48) & 0xFF),
                    static_cast<uint8_t>((targetAddress.imm.value.u >> 56) & 0xFF)
                };
                memcpy(buffer, newJump, sizeof(newJump));

                spdlog::info("Resolved opaque predicate at 0x{0:x} with absolute jump patch!",
                             analyzerState.jumpInstruction->offsetFromDllBase);
            }
        }
    } else {
        memset(
            analyzerState.jumpInstruction->dumpInfo->DumpInfo->ImageBuffer.get() +
            analyzerState.jumpInstruction->offsetFromDllBase, 0x90,
            originalLength);
        spdlog::info("Resolved opaque predicate at 0x{0:x} by nopping out the jump!",
                     analyzerState.jumpInstruction->offsetFromDllBase);
    }
}

static constexpr std::pair<int, PatternAnalyzer<StackOpaqueAnalyzerState>::PatternMatcher> stackOpaqueAnalyzerPatterns[]
        = {
            {
                0, [](const std::shared_ptr<DecodedInstruction> &instruction, StackOpaqueAnalyzerState &analyzerState) {
                    if (IsMoveImmediateValueToStackInstruction(instruction)) {
                        analyzerState.moveValueToStackInstruction = instruction;
                        analyzerState.stackOffset = instruction->operands[0].mem.disp.value;
                        analyzerState.stackValue = instruction->operands[1].imm.value.u;
                        return MatcherResult{true};
                    }

                    return MatcherResult{false};
                }
            },

            {
                1, [](const std::shared_ptr<DecodedInstruction> &instruction, StackOpaqueAnalyzerState &analyzerState) {
                    if (IsMoveStackValueToRegisterInstruction(instruction, analyzerState)) {
                        analyzerState.moveStackValueToRegisterInstruction = instruction;
                        analyzerState.firstCompareRegister = instruction->operands[0].reg.value;
                        return MatcherResult{true};
                    }
                    return MatcherResult{false};
                }
            },

            {
                2, [](const std::shared_ptr<DecodedInstruction> &instruction, StackOpaqueAnalyzerState &analyzerState) {
                    if (IsCompareValuesInstruction(instruction, analyzerState)) {
                        analyzerState.compareInstruction = instruction;
                        analyzerState.comparedAgainst = instruction->operands[1].imm.value.u;
                        return MatcherResult{true};
                    }
                    return MatcherResult{false};
                }
            },

            {
                3, [](const std::shared_ptr<DecodedInstruction> &instruction, StackOpaqueAnalyzerState &analyzerState) {
                    if (IsJumpInstruction(instruction)) {
                        analyzerState.jumpInstruction = instruction;
                        return MatcherResult{true};
                    }
                    return MatcherResult{false};
                }
            },
        };

const std::pair<int, PatternAnalyzer<StackOpaqueAnalyzerState>::PatternMatcher> *
StackOpaqueAnalyzer::getPatterns() const {
    return stackOpaqueAnalyzerPatterns;
}

size_t StackOpaqueAnalyzer::getPatternsCount() const {
    return 3;
}

size_t StackOpaqueAnalyzer::getFinalProgress() const {
    return 4;
}

void StackOpaqueAnalyzer::onPatternMatched() {
    ResolveStackOpaquePredicate(currentAnalyzerState);
}

static auto stackOpaqueAnalyzer = StackOpaqueAnalyzer();

void AnalyzeInstructionForOpaquePredicates(const std::shared_ptr<DecodedInstruction> &instruction) {
    stackOpaqueAnalyzer.analyzeInstruction(instruction);
}
