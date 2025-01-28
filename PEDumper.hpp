//
// Created by Pixeluted on 27/01/2025.
//
#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <Windows.h>

#define PAGE_SIZE 0x1000

struct PEDumpResults {
    uintptr_t DllBase; // The base of the Dll in Roblox Memory
    size_t ImageSize; // The size of the image (and our buffer)
    std::shared_ptr<uint8_t[]> ImageBuffer; // The buffer where the whole dumped image is stored
    struct codeSectionInfo {
        uintptr_t codeSectionStartOffset; // The offset from the DllBase or Buffer start
        size_t codeSectionSize; // The size of the code section
    };
    codeSectionInfo CodeSectionInfo; // Contains information about the code section
};

/**
 * @brief Dumps a module from a running process and returns a structure with all the info.
 * @param processHandle A handle to the process which we want to dump the module from
 * @param moduleName The full module name (ex: ntdll.dll)
 * @param codeSectionName The name of the section that contains executable code
 * @return A optional PEDumpResults structure
 */
std::optional<PEDumpResults> DumpModule(HANDLE processHandle, const std::string& moduleName, const std::string& codeSectionName);
