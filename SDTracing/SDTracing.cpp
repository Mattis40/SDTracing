#include <iostream>
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <atomic>
#include <conio.h>
#include <tlhelp32.h>

#define KERNEL_LOGGER_NAME L"NT Kernel Logger"

// Explicitly declare the SystemTraceControlGuid
EXTERN_C const GUID SystemTraceControlGuid = { 0x9e814aad, 0x3204, 0x11d2, { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };

std::atomic<bool> stopProcessing(false);

std::wstring GetProcessNameByPid(DWORD processID) {
    std::wstring processName = L"<unknown>";
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hProcessSnap, &pe32)) {
            do {
                if (pe32.th32ProcessID == processID) {
                    processName = pe32.szExeFile;
                    break;
                }
            } while (Process32Next(hProcessSnap, &pe32));
        }
        CloseHandle(hProcessSnap);
    }
    return processName;
}

void WINAPI EventRecordCallback(EVENT_RECORD* pEvent)
{
    if (stopProcessing) {
        return;
    }

    if (pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_IO_READ) {
		std::wstring processName = GetProcessNameByPid(pEvent->EventHeader.ProcessId);
        std::wcout << L"Read detected for Process ID: " << pEvent->EventHeader.ProcessId << " (" << processName << ")" << std::endl;
    }
    else if (pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_IO_WRITE) {
		std::wstring processName = GetProcessNameByPid(pEvent->EventHeader.ProcessId);
        std::wcout << L"Write detected for Process ID: " << pEvent->EventHeader.ProcessId << " (" << processName << ")" << std::endl;
    }
}

void processTrace(TRACEHANDLE hTrace)
{
    while (!stopProcessing) {
        ULONG status = ProcessTrace(&hTrace, 1, nullptr, nullptr);
        if (status != ERROR_SUCCESS) {
            std::cerr << "Failed to process trace. Error: " << status << std::endl;
            break;
        }
    }
}

int main()
{
    TRACEHANDLE hTrace = 0;
    EVENT_TRACE_LOGFILE logFile = {};
    EVENT_TRACE_PROPERTIES* pSessionProperties = nullptr;
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);
    ULONG status = ERROR_SUCCESS;

    // Allocate memory for the session properties
    pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (pSessionProperties == nullptr) {
        std::cerr << "Failed to allocate memory for session properties." << std::endl;
        return 1;
    }
    ZeroMemory(pSessionProperties, bufferSize);

    // Set the session properties
    pSessionProperties->Wnode.BufferSize = bufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1; // QPC clock resolution
    pSessionProperties->Wnode.Guid = SystemTraceControlGuid;
    pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pSessionProperties->EnableFlags = EVENT_TRACE_FLAG_DISK_IO; // Enable disk I/O events
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    // Start the kernel logger session
    std::cout << "Starting kernel logger session..." << std::endl;
    status = StartTrace(&hTrace, KERNEL_LOGGER_NAME, pSessionProperties);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        std::cerr << "Failed to start kernel logger session. Error: " << status << std::endl;
        free(pSessionProperties);
        return 1;
    }
    std::cout << "Kernel logger session started successfully." << std::endl;

    // Configure the log file
    ZeroMemory(&logFile, sizeof(EVENT_TRACE_LOGFILE));
    logFile.LoggerName = (LPWSTR)KERNEL_LOGGER_NAME;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(EventRecordCallback);

    // Open the trace
    std::cout << "Opening trace..." << std::endl;
    hTrace = OpenTrace(&logFile);
    if (hTrace == (TRACEHANDLE)INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open trace. Error: " << GetLastError() << std::endl;
        free(pSessionProperties);
        return 1;
    }
    std::cout << "Trace opened successfully." << std::endl;

    // Start processing trace in the main thread
    std::cout << "Press 'q' to stop tracing" << std::endl;

    // Process trace and check for user input
    while (!stopProcessing) {
        if (_kbhit() && _getch() == 'q') {
            stopProcessing = true;
        }
        processTrace(hTrace);
    }

    // Close the trace
    std::cout << "Closing trace..." << std::endl;
    status = CloseTrace(hTrace);
    if (status != ERROR_SUCCESS) {
        std::cerr << "Failed to close trace. Error: " << status << std::endl;
        free(pSessionProperties);
        return 1;
    }
    std::cout << "Trace closed successfully." << std::endl;

    // Stop the kernel logger session
    std::cout << "Stopping kernel logger session..." << std::endl;
    status = ControlTrace(0, KERNEL_LOGGER_NAME, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
    if (status != ERROR_SUCCESS) {
        std::cerr << "Failed to stop kernel logger session. Error: " << status << std::endl;
        free(pSessionProperties);
        return 1;
    }
    std::cout << "Kernel logger session stopped successfully." << std::endl;

    free(pSessionProperties);
    return 0;
}
