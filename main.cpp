#include <fstream>
#include <Windows.h>
#include <psapi.h>
#include <optional>
#include <TlHelp32.h>
#include <capstone/capstone.h>
#include <spdlog/spdlog.h>

#include "Dumper.hpp"
#include "PEDumper.hpp"

std::optional<HANDLE> GetProcessHandleByName(const std::string &processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    PROCESSENTRY32 processEntry = {sizeof(PROCESSENTRY32)};
    if (Process32First(snapshot, &processEntry)) {
        do {
            if (_stricmp(processName.c_str(), processEntry.szExeFile) == 0) {
                HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processEntry.th32ProcessID);
                CloseHandle(snapshot);
                return handle;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return std::nullopt;
}

uint64_t resolveRIPRelativeAddress(const cs_insn *instruction) {
    const int64_t displacement = instruction->detail->x86.operands[1].mem.disp;
    const uint64_t nextInstructionAddr = instruction->address + instruction->size;
    const uint64_t targetAddress = nextInstructionAddr + displacement;

    return targetAddress;
}



int main() {
    spdlog::set_pattern("[%^%l%$] %v");

    const auto robloxHandleOpt = GetProcessHandleByName("RobloxPlayerBeta.exe");
    if (!robloxHandleOpt.has_value()) {
        spdlog::error("Roblox isn't open, or we failed to obtain a handle!");
        return -1;
    }
    const auto robloxHandle = robloxHandleOpt.value();
    const auto _dumpResultsOpt = DumpModule(robloxHandle, "RobloxPlayerBeta.dll", ".byfron");
    if (!_dumpResultsOpt.has_value()) {
        spdlog::error("Failed to dump hyperion module!");
        return -1;
    }
    auto dumpResults = _dumpResultsOpt.value();

    auto dumperInfo = DumperInfo{};
    dumperInfo.DumpInfo = &dumpResults;
    dumperInfo.RobloxHandle = robloxHandle;

    csh CapstoneHandle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &CapstoneHandle) != CS_ERR_OK) {
        spdlog::error("Failed to initialize capstone handle!");
        return -1;
    }
    dumperInfo.CapstoneHandle = &CapstoneHandle;

    cs_option(CapstoneHandle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn *disassembledInstructions;
    const auto instructionsCount = cs_disasm(CapstoneHandle,
                                             dumpResults.ImageBuffer.get() + dumpResults.CodeSectionInfo.
                                             codeSectionStartOffset,
                                             dumpResults.CodeSectionInfo.codeSectionSize,
                                             dumpResults.DllBase + dumpResults.CodeSectionInfo.codeSectionStartOffset,
                                             0, &disassembledInstructions);
    cs_option(CapstoneHandle, CS_OPT_SKIPDATA, CS_OPT_OFF);

    dumperInfo.DisassembledInstructions = disassembledInstructions;
    dumperInfo.DisassembledInstructionsCount = instructionsCount;

    spdlog::info("Successfully disassembled {} instructions!", instructionsCount);

    return 0;

}
