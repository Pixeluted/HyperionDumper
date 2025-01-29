//
// Created by Pixeluted on 29/01/2025.
//
#pragma once
#include <memory>
#include <Zydis/Zydis.h>

struct DecodedInstruction {
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    uintptr_t offsetFromDllBase;
};

class Dissassembler {
    static std::shared_ptr<Dissassembler> instance;

    ZydisDecoder zydisDecoder;
    ZydisFormatter zydisFormatter;

public:
    static std::shared_ptr<Dissassembler> GetSingleton();

    Dissassembler();

    /**
     * @brief Disassembles instructions in given buffer and calls a callback for each instruction
     * @tparam T The type of the function that should be called on each instruction disassembled
     * @param bufferAddress The start address of the buffer in our process
     * @param bufferSize The size of the buffer
     * @param perInstructionCallback The function that should be called on each instruction
     * @param inferredAddress The address base that will be used instead of our process addresses (defaults to bufferAddress)
     */
    template<typename T>
    void DissassembleInstructions(const uintptr_t bufferAddress, const size_t bufferSize, T perInstructionCallback, const uintptr_t inferredAddress = bufferAddress) {
        size_t currentBufferOffset = 0;
        ZydisDecodedInstruction currentInstruction;
        ZydisDecodedOperand currentOperands[ZYDIS_MAX_OPERAND_COUNT];
        ZyanStatus currentStatus;

        do {
            currentStatus = ZydisDecoderDecodeFull(&zydisDecoder,
                                                   reinterpret_cast<const void *>(bufferAddress + currentBufferOffset),
                                                   bufferSize - currentBufferOffset, &currentInstruction,
                                                   currentOperands);
            if (ZYAN_SUCCESS(currentStatus)) {
                auto fullInstruction = DecodedInstruction{};
                fullInstruction.instruction = currentInstruction;
                fullInstruction.offsetFromDllBase = currentBufferOffset;
                memcpy(fullInstruction.operands, currentOperands, sizeof(currentOperands));

                perInstructionCallback(fullInstruction, inferredAddress + currentBufferOffset);

                currentBufferOffset += currentInstruction.length;
            } else {
                currentBufferOffset += 1;
            }
        } while (currentStatus != ZYDIS_STATUS_NO_MORE_DATA && (bufferSize - currentBufferOffset) > 0);
    }

    void PrintOutInstruction(const DecodedInstruction& instruction, const uintptr_t instructionAddress);
};
