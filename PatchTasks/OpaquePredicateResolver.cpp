//
// Created by Pixeluted on 29/01/2025.
//

#include "OpaquePredicateResolver.hpp"

#include <spdlog/spdlog.h>

static auto stackOpaquePredicateData = StackOpaquePredicateData{};

bool IsMoveImmediateValueToStackInstruction(const std::shared_ptr<DecodedInstruction> &instruction) {
    return instruction->instruction->mnemonic == ZYDIS_MNEMONIC_MOV &&
           instruction->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
           instruction->operands[0].mem.base == ZYDIS_REGISTER_RSP &&
           instruction->operands[0].mem.disp.value != 0 &&
           instruction->operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
}

bool IsMoveStackValueToRegisterInstruction(const std::shared_ptr<DecodedInstruction> &instruction) {
    return instruction->instruction->mnemonic == ZYDIS_MNEMONIC_MOV &&
           instruction->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
           instruction->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
           instruction->operands[1].mem.base == ZYDIS_REGISTER_RSP &&
           instruction->operands[1].mem.disp.value == stackOpaquePredicateData.stackOffset;
}

bool IsCompareValuesInstruction(const std::shared_ptr<DecodedInstruction> &instruction) {
    return instruction->instruction->mnemonic == ZYDIS_MNEMONIC_CMP &&
           instruction->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
           instruction->operands[0].reg.value == stackOpaquePredicateData.firstCompareRegister &&
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

bool WillStackOpaquePredicateJump() {
    if (stackOpaquePredicateData.currentProgress != 4)
        return false;

    switch (stackOpaquePredicateData.jumpInstruction->instruction->mnemonic) {
        case ZYDIS_MNEMONIC_JZ:
            return stackOpaquePredicateData.stackValue == stackOpaquePredicateData.comparedAgainst;
        case ZYDIS_MNEMONIC_JNZ:
            return stackOpaquePredicateData.stackValue != stackOpaquePredicateData.comparedAgainst;
        case ZYDIS_MNEMONIC_JNBE:
            return stackOpaquePredicateData.stackValue > stackOpaquePredicateData.comparedAgainst;
        case ZYDIS_MNEMONIC_JNB:
            return stackOpaquePredicateData.stackValue >= stackOpaquePredicateData.comparedAgainst;
        case ZYDIS_MNEMONIC_JB:
            return stackOpaquePredicateData.stackValue < stackOpaquePredicateData.comparedAgainst;
        case ZYDIS_MNEMONIC_JBE:
            return stackOpaquePredicateData.stackValue <= stackOpaquePredicateData.comparedAgainst;
        default:
            return false;
    }
}

void ResolveStackOpaquePredicate() {
    if (stackOpaquePredicateData.currentProgress != 4)
        return;

    const auto originalLength = stackOpaquePredicateData.jumpInstruction->instruction->length;

    const auto willJump = WillStackOpaquePredicateJump();
    if (willJump) {
        const auto targetAddress = stackOpaquePredicateData.jumpInstruction->operands[0];
        const auto buffer = stackOpaquePredicateData.jumpInstruction->dumpInfo->DumpInfo->ImageBuffer.get() +
                            stackOpaquePredicateData.jumpInstruction->offsetFromDllBase;

        if (targetAddress.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if (targetAddress.size == 8) {
                memset(buffer, 0x90, originalLength);
                const uint8_t newJump[] = {
                    0xEB, static_cast<uint8_t>(targetAddress.imm.value.u)
                };
                memcpy(buffer, newJump, sizeof(newJump));

                spdlog::info("Resolved opaque predicate at 0x{0:x} with short relative jump patch!",
                             stackOpaquePredicateData.jumpInstruction->offsetFromDllBase);
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
                             stackOpaquePredicateData.jumpInstruction->offsetFromDllBase);
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
                             stackOpaquePredicateData.jumpInstruction->offsetFromDllBase);
            }
        }
    } else {
        memset(
            stackOpaquePredicateData.jumpInstruction->dumpInfo->DumpInfo->ImageBuffer.get() +
            stackOpaquePredicateData.jumpInstruction->offsetFromDllBase, 0x90,
            originalLength);
        spdlog::info("Resolved opaque predicate at 0x{0:x} by nopping out the jump!",
                     stackOpaquePredicateData.jumpInstruction->offsetFromDllBase);
    }
}

void StackOpaquePredicateAnalyzor(const std::shared_ptr<DecodedInstruction> &instruction,
                                  const bool isRecheck = false) {
    if (stackOpaquePredicateData.currentProgress == 0 &&
        IsMoveImmediateValueToStackInstruction(instruction)) {
        stackOpaquePredicateData.moveValueToStackInstruction = instruction;
        stackOpaquePredicateData.stackOffset = instruction->operands[0].mem.disp.value;
        stackOpaquePredicateData.stackValue = instruction->operands[1].imm.value.u;
        stackOpaquePredicateData.currentProgress = 1;
        return;
    }

    if (stackOpaquePredicateData.currentProgress == 1) {
        if (IsMoveStackValueToRegisterInstruction(instruction)) {
            stackOpaquePredicateData.moveStackValueToRegisterInstruction = instruction;
            stackOpaquePredicateData.firstCompareRegister = instruction->operands[0].reg.value;
            stackOpaquePredicateData.currentProgress = 2;
            return;
        } else {
            stackOpaquePredicateData.currentProgress = 0;
            if (isRecheck == false) {
                StackOpaquePredicateAnalyzor(instruction, true);
            }
        }
    }

    if (stackOpaquePredicateData.currentProgress == 2) {
        if (IsCompareValuesInstruction(instruction)) {
            stackOpaquePredicateData.compareInstruction = instruction;
            stackOpaquePredicateData.comparedAgainst = instruction->operands[1].imm.value.u;
            stackOpaquePredicateData.currentProgress = 3;
            return;
        } else {
            stackOpaquePredicateData.currentProgress = 0;
            if (isRecheck == false) {
                StackOpaquePredicateAnalyzor(instruction, true);
            }
            return;
        }
    }

    if (stackOpaquePredicateData.currentProgress == 3) {
        if (IsJumpInstruction(instruction)) {
            stackOpaquePredicateData.jumpInstruction = instruction;
            stackOpaquePredicateData.currentProgress = 4;
            return;
        } else {
            stackOpaquePredicateData.currentProgress = 0;
            if (isRecheck == false) {
                StackOpaquePredicateAnalyzor(instruction, true);
            }
            return;
        }
    }

    if (stackOpaquePredicateData.currentProgress == 4) {
        ResolveStackOpaquePredicate();
        stackOpaquePredicateData.currentProgress = 0;
    }
}

void AnalyzeInstructionForOpaquePredicates(const std::shared_ptr<DecodedInstruction> &instruction) {
    StackOpaquePredicateAnalyzor(instruction);
}
