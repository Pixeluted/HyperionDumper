//
// Created by Pixeluted on 27/01/2025.
//

#include "PEDumper.hpp"
#include <psapi.h>
#include <spdlog/spdlog.h>

std::optional<MODULEINFO> GetModuleInfoInProcess(const HANDLE processHandle, const std::string &moduleName) {
    DWORD Needed;
    HMODULE ModuleHandles[1024];

    EnumProcessModulesEx(processHandle, ModuleHandles, sizeof(ModuleHandles), &Needed,
                         LIST_MODULES_32BIT | LIST_MODULES_64BIT);
    for (int i = 0; i < (Needed / sizeof(HMODULE)); i++) {
        char CurrentModuleName[MAX_PATH];
        GetModuleFileNameExA(processHandle, ModuleHandles[i], CurrentModuleName, sizeof(CurrentModuleName));
        if (strstr(CurrentModuleName, moduleName.c_str())) {
            HMODULE Module = ModuleHandles[i];
            MODULEINFO ModuleInformation;

            GetModuleInformation(processHandle, Module, &ModuleInformation, sizeof(MODULEINFO));
            return ModuleInformation;
        }
    }

    return std::nullopt;
}

std::optional<PEDumpResults> DumpModule(HANDLE processHandle, const std::string &moduleName,
                                        const std::string &codeSectionName) {
    const auto _moduleInfoOpt = GetModuleInfoInProcess(processHandle, moduleName);
    if (!_moduleInfoOpt.has_value()) {
        spdlog::error("Failed to obtain module information for the module: {}", moduleName);
        return std::nullopt;
    }
    const auto moduleInfo = _moduleInfoOpt.value();
    const auto moduleBaseConverted = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);

    auto dumpResults = PEDumpResults{};
    dumpResults.DllBase = moduleBaseConverted;
    dumpResults.ImageSize = moduleInfo.SizeOfImage;
    dumpResults.ImageBuffer = std::make_shared<uint8_t[]>(moduleInfo.SizeOfImage);

    // Temporary buffer for PE headers as we need to read them and edit them before we can start dumping
    // First memory page is always PE headers
    auto peHeadersBuffer = std::make_unique<uint8_t[]>(PAGE_SIZE);
    if (!ReadProcessMemory(processHandle, moduleInfo.lpBaseOfDll, peHeadersBuffer.get(), PAGE_SIZE, nullptr)) {
        spdlog::error("Failed to read PE headers for module {0}! Error: 0x{1:x}", moduleName, GetLastError());
        return std::nullopt;
    }

    const auto dosHeaders = reinterpret_cast<PIMAGE_DOS_HEADER>(peHeadersBuffer.get());
    const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(peHeadersBuffer.get() + dosHeaders->e_lfanew);

    auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
        // We need to point RawSize and PointerToRawData to the Virtual equivalents or any reverse engineering tool will die
        sectionHeader->PointerToRawData = sectionHeader->VirtualAddress;
        sectionHeader->SizeOfRawData = sectionHeader->Misc.VirtualSize;

        // No reason to dump a section with no data
        if (sectionHeader->Misc.VirtualSize == 0)
            continue;

        const auto sectionName = std::string(reinterpret_cast<const char *>(sectionHeader->Name));
        // The full address in the process memory of this section start
        const auto sectionStartAddress = moduleBaseConverted + sectionHeader->VirtualAddress;
        // The offset we can use from the dll base and image buffer start
        const auto sectionStartOffset = sectionStartAddress - moduleBaseConverted;

        // We need to ignore few sections, those are
        // * .data - Manipulated at runtime, not useful for us
        // * .reloc - Contains relocation data which we don't need for a dump
        // * .rsrc - Contains same data as .reloc
        // We then fill those sections with 0xCC to make sure there isn't any data
        if (sectionName.find(".data") != std::string::npos || sectionName.find(".reloc") != std::string::npos ||
            sectionName.find(".rsrc") != std::string::npos) {
            memset(dumpResults.ImageBuffer.get() + sectionStartOffset, 0xCC, sectionHeader->Misc.VirtualSize);
            continue;
        }

        // We found the requested section which is executable, we now need to fill in the data in the result structure
        if (strcmp(sectionName.c_str(), codeSectionName.c_str()) == 0) {
            dumpResults.CodeSectionInfo.codeSectionStartOffset = sectionStartOffset;
            dumpResults.CodeSectionInfo.codeSectionSize = sectionHeader->Misc.VirtualSize;
        }

        // To dump the section, we will read by each memory page to ensure we read the most data (if some pages are not accessible)
        for (uintptr_t currentOffset = 0; currentOffset < sectionHeader->Misc.VirtualSize;) {
            // To account for different page boundaries than the normal page size, we need to use the minimal size
            const auto readSize = min(sectionHeader->Misc.VirtualSize - currentOffset, PAGE_SIZE);
            // The full address we can use to read from the process memory
            const auto fullAddress = sectionStartAddress + currentOffset;
            // The offset from dll base we can use for our image buffer
            const auto bufferOffset = fullAddress - moduleBaseConverted;

            if (!ReadProcessMemory(processHandle, reinterpret_cast<LPVOID>(fullAddress),
                                   dumpResults.ImageBuffer.get() + bufferOffset, readSize, nullptr)) {
                // If we couldn't read the memory page, just fill it with 0xCC
                memset(dumpResults.ImageBuffer.get() + bufferOffset, 0xCC, readSize);
                spdlog::debug("Failed to read memory page 0x{0:x} in section {1}, filling it with 0xCC!", fullAddress,
                              sectionName);
            } else {
                spdlog::debug("Successfully read memory page 0x{0:x} in section {1} with size 0x{2:x}!", fullAddress,
                              sectionName, readSize);
            }

            currentOffset += readSize;
        }
    }

    // We now have everything dumped, we now just need to copy our edited PE headers to the image buffer
    memcpy(dumpResults.ImageBuffer.get(), peHeadersBuffer.get(), PAGE_SIZE);
    peHeadersBuffer.release(); // We no longer need the PE headers and we can delete it

    return dumpResults;
}
