#include <fstream>
#include <iostream>
#include <Windows.h>
#include <psapi.h>
#include <optional>
#include <TlHelp32.h>
#include <spdlog/spdlog.h>

#include "Dissassembler.hpp"
#include "PatchTasks/OpaquePredicateResolver.hpp"

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


int main() {
    spdlog::set_pattern("[%^%l%$] %v");

    const auto robloxHandleOpt = GetProcessHandleByName("RobloxPlayerBeta.exe");
    if (!robloxHandleOpt.has_value()) {
        spdlog::error("Roblox isn't open, or we failed to obtain a handle!");
        spdlog::info("Press enter to exit...");
        std::cin.get();
        return -1;
    }
    const auto robloxHandle = robloxHandleOpt.value();
    const auto _dumpResultsOpt = DumpModule(robloxHandle, "RobloxPlayerBeta.dll", ".byfron");
    if (!_dumpResultsOpt.has_value()) {
        spdlog::error("Failed to dump hyperion module!");
        spdlog::info("Press enter to exit...");
        std::cin.get();
        return -1;
    }
    auto dumpResults = _dumpResultsOpt.value();

    auto dumperInfo = DumperInfo{};
    dumperInfo.DumpInfo = &dumpResults;
    dumperInfo.RobloxHandle = robloxHandle;

    const auto disassembler = Dissassembler::GetSingleton();
    disassembler->DissassembleInstructions(
        reinterpret_cast<uintptr_t>(dumpResults.ImageBuffer.get() + dumpResults.CodeSectionInfo.codeSectionStartOffset),
        dumpResults.CodeSectionInfo.codeSectionSize,
        [](const std::shared_ptr<DecodedInstruction> &instruction,
                                            const uintptr_t runtimeAddress) {
            AnalyzeInstructionForOpaquePredicates(instruction);
        }, dumperInfo);

    spdlog::info("Resolved {} opaque predicates!", GetAmountOfResolvedOpaquePredicates());

    std::ofstream file("dump.bin", std::ios::binary);
    file.write(reinterpret_cast<const char*>(dumpResults.ImageBuffer.get()), dumpResults.ImageSize);
    file.close();

    spdlog::info("Wrote to dump.bin");
    spdlog::info("Press enter to exit...");
    std::cin.get();
    return 0;
}
