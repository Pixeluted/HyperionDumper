//
// Created by Pixeluted on 27/01/2025.
//
#pragma once
#include "capstone/capstone.h"
struct PEDumpResults;

struct DumperInfo {
    HANDLE RobloxHandle;
    csh* CapstoneHandle;
    PEDumpResults* DumpInfo;
    cs_insn* DisassembledInstructions;
    size_t DisassembledInstructionsCount;
};
