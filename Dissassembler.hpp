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
    DumperInfo* dumpInfo;
    uintptr_t offsetFromDllBase;
    uintptr_t offsetFromBuffer;
    uintptr_t originalMemoryAddress;
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
     * @param dumperInfo The dumper info so we can calculate offsets from dll base and original memory address
     */
    template<typename T>
    void DissassembleInstructions(const uintptr_t bufferAddress, const size_t bufferSize, T perInstructionCallback,
                                   DumperInfo &dumperInfo) {
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
                fullInstruction->dumpInfo = &dumperInfo;
                fullInstruction->offsetFromDllBase =
                        (dumperInfo
                         .DumpInfo->DllBase + dumperInfo.DumpInfo->CodeSectionInfo.codeSectionStartOffset +
                         currentBufferOffset) - dumperInfo
                        .DumpInfo->DllBase;
                fullInstruction->originalMemoryAddress = dumperInfo.DumpInfo->DllBase + fullInstruction->offsetFromDllBase;
                fullInstruction->offsetFromBuffer = currentBufferOffset;

                memcpy(fullInstruction->operands.get(), currentOperands,
                       sizeof(ZydisDecodedOperand) * ZYDIS_MAX_OPERAND_COUNT);

                perInstructionCallback(fullInstruction, fullInstruction->originalMemoryAddress);

                currentBufferOffset += currentInstruction.length;
            } else {
                currentBufferOffset += 1;
            }
        } while (currentStatus != ZYDIS_STATUS_NO_MORE_DATA && (bufferSize - currentBufferOffset) > 0);
    }

    /**
     * @brief Prints the instruction out to console
     * @param instruction The instruction to print
     */
    void PrintOutInstruction(const std::shared_ptr<DecodedInstruction> &instruction) const;

    /**
     * @brief Resolves RIP relative moves, or in other words PIC (Position Independent Code)
     * @param instruction The instruction that has RIP + offset operand as second operand
     * @return The resolved address
     */
    uintptr_t ResolveRIPRelativeInstruction(const std::shared_ptr<DecodedInstruction> &instruction);
};
