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

void StackOpaquePredicateAnalyzor(const std::shared_ptr<DecodedInstruction> &instruction, const bool isRecheck = false) {
    if (stackOpaquePredicateData.currentProgress == 0 &&
        IsMoveImmediateValueToStackInstruction(instruction)) {
        stackOpaquePredicateData.moveValueToStackInstruction = instruction;
        stackOpaquePredicateData.stackOffset = instruction->operands[0].mem.disp.value;
        stackOpaquePredicateData.stackValue = instruction->operands[1].imm.value.s;
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
            stackOpaquePredicateData.comparedAgainst = instruction->operands[1].imm.value.s;
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
        // If we are this point, we are almost guaranteed to have some jump instruction here, so lets just set it
        stackOpaquePredicateData.jumpInstruction = instruction;
    }

    if (stackOpaquePredicateData.currentProgress == 3 ) {
        spdlog::info("Found resolvable opaque predicate at 0x{0:x}!", stackOpaquePredicateData.moveValueToStackInstruction->offsetFromDllBase);
        spdlog::info("Constants: Moved to stack 0x{0:x}, compared against 0x{1:x}", stackOpaquePredicateData.stackValue, stackOpaquePredicateData.comparedAgainst);
        spdlog::info("");
        stackOpaquePredicateData.currentProgress = 0;
    }
}

void AnalyzeInstructionForOpaquePredicates(const std::shared_ptr<DecodedInstruction> &instruction) {
    StackOpaquePredicateAnalyzor(instruction);
}
