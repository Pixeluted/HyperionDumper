//
// Created by Pixeluted on 29/01/2025.
//

#include "Dissassembler.hpp"

#include <spdlog/spdlog.h>

std::shared_ptr<Dissassembler> Dissassembler::instance;

std::shared_ptr<Dissassembler> Dissassembler::GetSingleton() {
    if (instance == nullptr)
        instance = std::make_shared<Dissassembler>();

    return instance;
}

Dissassembler::Dissassembler(): zydisDecoder(ZydisDecoder{}), zydisFormatter(ZydisFormatter{}) {
    ZydisDecoderInit(&zydisDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&zydisFormatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

void Dissassembler::PrintOutInstruction(const std::shared_ptr<DecodedInstruction> &instruction) const {
    char instructionBuffer[256];
    ZydisFormatterFormatInstruction(&zydisFormatter, instruction->instruction.get(), instruction->operands.get(),
                                    instruction->instruction->operand_count_visible, instructionBuffer,
                                    sizeof(instructionBuffer), instruction->originalMemoryAddress, ZYAN_NULL);

    spdlog::info("0x{0:x}: {1}", instruction->originalMemoryAddress, instructionBuffer);
}

uintptr_t Dissassembler::ResolveRIPRelativeInstruction(const std::shared_ptr<DecodedInstruction> &instruction) {
    const auto displacement = instruction->operands[1].mem.disp.value;
    const auto nextInstructionAddress = instruction->originalMemoryAddress + instruction->instruction->length;
    const auto targetAddress = nextInstructionAddress + displacement;

    return targetAddress;
}