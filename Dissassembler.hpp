//
// Created by Pixeluted on 29/01/2025.
//
#pragma once
#include <memory>
#include <Zydis/Zydis.h>

#include "PEDumper.hpp"
#include "Dumper.hpp"


struct DecodedInstruction {
    std::shared_ptr<ZydisDecodedInstruction> instruction;
    std::shared_ptr<ZydisDecodedOperand[ZYDIS_MAX_OPERAND_COUNT]> operands;
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
     * @param dllBase The address base that will be used instead of our process addresses (defaults to bufferAddress)
     */
    template<typename T>
    void DissassembleInstructions(const uintptr_t bufferAddress, const size_t bufferSize, T perInstructionCallback,
                                  const DumperInfo &dumperInfo) {
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
                auto fullInstruction = std::make_shared<DecodedInstruction>();
                fullInstruction->instruction = std::make_shared<ZydisDecodedInstruction>(currentInstruction);
                fullInstruction->operands = std::make_shared_for_overwrite<ZydisDecodedOperand[10]>();
                fullInstruction->offsetFromDllBase =
                        (dumperInfo
                         .DumpInfo->DllBase + dumperInfo.DumpInfo->CodeSectionInfo.codeSectionStartOffset +
                         currentBufferOffset) - dumperInfo
                        .DumpInfo->DllBase;
                memcpy(fullInstruction->operands.get(), currentOperands,
                       sizeof(ZydisDecodedOperand) * ZYDIS_MAX_OPERAND_COUNT);

                perInstructionCallback(fullInstruction, dumperInfo
                                                        .DumpInfo->DllBase + dumperInfo.DumpInfo->CodeSectionInfo.
                                                        codeSectionStartOffset + currentBufferOffset);

                currentBufferOffset += currentInstruction.length;
            } else {
                currentBufferOffset += 1;
            }
        } while (currentStatus != ZYDIS_STATUS_NO_MORE_DATA && (bufferSize - currentBufferOffset) > 0);
    }

    void PrintOutInstruction(const DecodedInstruction &instruction, const uintptr_t instructionAddress);
};
