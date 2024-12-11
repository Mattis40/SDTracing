#define INITGUID

#include <thread>
#include <windows.h>
#include <iostream>
#include <evntrace.h>
#include <tdh.h>
#include <conio.h>
#include <atomic>
#include <csignal>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <map>
#include "Timer.h"
#include <future>

DEFINE_GUID( /* 3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c */    DiskIoGuid, 0x3d6fa8d4, 0xfe05, 0x11d0, 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c);

std::atomic<bool> stopProcessing(false);
TRACEHANDLE hTrace = 0;

double total_read_bytes = 0;
double total_write_bytes = 0;
double energy = 0;

// Helper to extract a field's value from the event
ULONG GetDataField(EVENT_RECORD* pEvent, LPCWSTR propertyName, PBYTE buffer, ULONG bufferSize) {
	// First, retrieve event metadata
	DWORD bufferSizeNeeded = 0;
	PTRACE_EVENT_INFO pInfo = nullptr;

	// Get the size of the event information
	ULONG status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufferSizeNeeded);
	if (status == ERROR_INSUFFICIENT_BUFFER) {
		pInfo = (PTRACE_EVENT_INFO)malloc(bufferSizeNeeded);
		if (!pInfo) {
			std::cerr << "Failed to allocate memory for TRACE_EVENT_INFO." << std::endl;
			return ERROR_OUTOFMEMORY;
		}

		status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufferSizeNeeded);
	}

	if (status != ERROR_SUCCESS) {
		std::cerr << "TdhGetEventInformation failed. Error: " << status << std::endl;
		if (pInfo) free(pInfo);
		return status;
	}

	// Find the property index for the requested property name
	for (DWORD i = 0; i < pInfo->PropertyCount; i++) {
		EVENT_PROPERTY_INFO& propInfo = pInfo->EventPropertyInfoArray[i];
		PWSTR currentPropertyName = (PWSTR)((PBYTE)pInfo + propInfo.NameOffset);

		if (wcscmp(currentPropertyName, propertyName) == 0) {
			// We found the property; now fetch its value
			PROPERTY_DATA_DESCRIPTOR dataDescriptor;
			dataDescriptor.PropertyName = (ULONGLONG)((PBYTE)pInfo + propInfo.NameOffset);
			dataDescriptor.ArrayIndex = ULONG_MAX;  // Not an array

			status = TdhGetProperty(pEvent, 0, nullptr, 1, &dataDescriptor, bufferSize, buffer);
			if (status != ERROR_SUCCESS) {
				std::cerr << "TdhGetProperty failed. Error: " << status << std::endl;
			}

			free(pInfo);
			return status;
		}
	}

	free(pInfo);  // Clean up metadata
	return ERROR_NOT_FOUND;
}

double energy_calculation(double total_read, double total_write, double interval_ms) {
	std::cout << "Calculating energy..." << std::endl;
	double total_energy = 0;

	double interval_s = interval_ms / 1000;

	long read_rate = total_read / interval_s;
	long write_rate = total_write / interval_s;

	double read_power = 2.2 * (double)read_rate / 5600000000;
	double write_power = 2.2 * (double)write_rate / 5300000000;

	double avg_power = read_power + write_power;

	double interval_energy = avg_power * interval_s;

	total_energy += interval_energy;

	std::cout << "Total energy: " << total_energy << std::endl;

	return total_energy;
}

void my_callback() {
	std::cout << "Callback called" << std::endl;
	std::cout << "Total read bytes: " << total_read_bytes << std::endl;
	std::cout << "Total write bytes: " << total_write_bytes << std::endl;
	std::future<double> energy_future = std::async(std::launch::async, energy_calculation, total_read_bytes, total_write_bytes, 500);

	total_read_bytes = 0;
	total_write_bytes = 0;

	energy += energy_future.get();
	std::cout << "Energy: " << energy << std::endl;
}

// Function to get the process name by process ID
std::wstring GetProcessNameByPid(DWORD processID) {
	std::wstring processName = L"<unknown>";

	// Try using OpenProcess for non-system processes first to get the process image name 
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	if (hProcess) {
		// Allocate a buffer to store the full path of the process image name
		WCHAR buffer[MAX_PATH];
		// Initialize the buffer size to the maximum path length 
		DWORD size = MAX_PATH;

		// Query the process image name using QueryFullProcessImageName API function 
		if (QueryFullProcessImageName(hProcess, 0, buffer, &size)) {
			// Extract the process name from the full path 
			processName = buffer;
		}
		// Close the process handle
		CloseHandle(hProcess);
	}
	else {
		// Check if OpenProcess failed due to permission issues
		if (GetLastError() == ERROR_ACCESS_DENIED) {
			// Fall back to CreateToolhelp32Snapshot for system processes
			HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			// Check if the snapshot was created successfully 
			if (hProcessSnap != INVALID_HANDLE_VALUE) {
				// Initialize the PROCESSENTRY32 structure
				PROCESSENTRY32 pe32;
				pe32.dwSize = sizeof(PROCESSENTRY32);
				// Iterate through the processes in the snapshot
				if (Process32First(hProcessSnap, &pe32)) {
					do {
						// Check if the process ID matches the target process ID
						if (pe32.th32ProcessID == processID) {
							// Extract the process name from the PROCESSENTRY32 structure
							processName = pe32.szExeFile;
							break;
						}
					} while (Process32Next(hProcessSnap, &pe32));
				}
				// Close the process snapshot handle
				CloseHandle(hProcessSnap);
			}
		}
	}

	return processName;
}

struct IoEventInfo {
	DWORD pid;
	std::wstring processName;
	USHORT operationType;
	ULONG bytesTransferred = 0;  // Track total bytes transferred for each IRP
};

// Global map to store initiation events by IRP address
std::map<ULONGLONG, IoEventInfo> ioEvents;
void WINAPI EventRecordCallback(EVENT_RECORD* pEvent) {
	if (stopProcessing) return;

	ULONG dataSize = 0;
	ULONGLONG irpAddress = 0;

	// Retrieve the IRP address and TransferSize
	GetDataField(pEvent, L"Irp", (PBYTE)&irpAddress, sizeof(ULONGLONG));
	GetDataField(pEvent, L"TransferSize", (PBYTE)&dataSize, sizeof(ULONG));

	IoEventInfo eventInfo;
	eventInfo.pid = pEvent->EventHeader.ProcessId;
	eventInfo.processName = GetProcessNameByPid(eventInfo.pid);  // Helper for process name

	switch (pEvent->EventHeader.EventDescriptor.Opcode) {
	case EVENT_TRACE_TYPE_IO_READ_INIT:
	case EVENT_TRACE_TYPE_IO_WRITE_INIT:
		eventInfo.operationType = pEvent->EventHeader.EventDescriptor.Opcode;
		ioEvents[irpAddress] = eventInfo;
		break;

	case EVENT_TRACE_TYPE_IO_READ:
		if (ioEvents.find(irpAddress) != ioEvents.end()) {
			total_read_bytes += dataSize;
			
		}
		break;
	case EVENT_TRACE_TYPE_IO_WRITE:
		if (ioEvents.find(irpAddress) != ioEvents.end()) {
			total_write_bytes += dataSize;
		}
		break;

	default:
		break;
	}
}

// Function to process the trace events in a loop until the stopProcessing flag is set to true
void processTrace() {
	while (!stopProcessing) {
		// Process the trace events using the ProcessTrace API function
		ULONG status = ProcessTrace(&hTrace, 1, nullptr, nullptr);
		if (status != ERROR_SUCCESS) {
			std::cerr << "Failed to process trace. Error: " << status << std::endl;
			break;
		}
	}
}

// Signal handler function to handle Ctrl + C signal for graceful termination
void signalHandler(int signal) {
	std::cout << "Signal received: " << signal << std::endl;
	stopProcessing = true;
	if (hTrace != 0) {
		std::cout << "Cancelling trace..." << std::endl;
		ControlTrace(hTrace, KERNEL_LOGGER_NAME, nullptr, EVENT_TRACE_CONTROL_STOP);
		CloseTrace(hTrace);
	}
}

// Function to stop any existing kernel logger session
void stopExistingKernelLogger() {
	// Initialize the EVENT_TRACE_PROPERTIES
	EVENT_TRACE_PROPERTIES properties = {};
	properties.Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES);
	properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;

	// Try to stop the logger if it exists
	ULONG status = ControlTrace(0, KERNEL_LOGGER_NAME, &properties, EVENT_TRACE_CONTROL_STOP);
	if (status == ERROR_SUCCESS) {
		std::cout << "Stopped an existing kernel logger session." << std::endl;
	}
	else if (status == ERROR_WMI_INSTANCE_NOT_FOUND) {
		std::cout << "No existing kernel logger session found." << std::endl;
	}
	else {
		std::cerr << "Failed to stop existing logger session. Error: " << status << std::endl;
	}
}

bool stopKernelLogger(EVENT_TRACE_PROPERTIES* sessionProperties) {
	ULONG status = ERROR_SUCCESS;
	std::cout << "Stopping kernel logger session..." << std::endl;
	status = ControlTrace(0, KERNEL_LOGGER_NAME, sessionProperties, EVENT_TRACE_CONTROL_STOP);
	if (status != ERROR_SUCCESS) {
		std::cerr << "Failed to stop kernel logger session. Error: " << status << std::endl;
		return 1;
	}
}

bool startTracing(EVENT_TRACE_PROPERTIES* sessionProperties) {
	ULONG status = ERROR_SUCCESS;
	// Start the kernel logger session with the specified session properties
	std::cout << "Starting kernel logger session..." << std::endl;
	status = StartTrace(&hTrace, KERNEL_LOGGER_NAME, sessionProperties);
	if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
		std::cerr << "Failed to start kernel logger session. Error: " << status << std::endl;
		free(sessionProperties);
		return false;
	}
}

void initializeTraceProperties(EVENT_TRACE_PROPERTIES* sessionProperties, ULONG bufferSize, ULONG flags...) {
	// Initialize the session properties with default values and flags 
	ZeroMemory(sessionProperties, bufferSize);
	sessionProperties->Wnode.BufferSize = bufferSize;
	sessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	sessionProperties->Wnode.ClientContext = 1;
	sessionProperties->Wnode.Guid = SystemTraceControlGuid;
	// Set the log file mode to real-time and enable disk I/O init flags
	sessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	sessionProperties->EnableFlags = flags;
	sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
}

void initializeLogFile(EVENT_TRACE_LOGFILE logFile) {
	// Initialize the log file properties for the kernel logger session
	ZeroMemory(&logFile, sizeof(EVENT_TRACE_LOGFILE));
	logFile.LoggerName = (LPWSTR)KERNEL_LOGGER_NAME;
	// Set the log file mode to real-time and event record callback function
	logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	logFile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(EventRecordCallback);
}

int main() {
	signal(SIGINT, signalHandler);

	stopExistingKernelLogger();

	// Initialize the EVENT_TRACE_PROPERTIES
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

	initializeTraceProperties(pSessionProperties, bufferSize, EVENT_TRACE_FLAG_DISK_IO_INIT | EVENT_TRACE_FLAG_DISK_IO);

	startTracing(pSessionProperties);

	//initializeLogFile(&logFile);

	ZeroMemory(&logFile, sizeof(EVENT_TRACE_LOGFILE));
	logFile.LoggerName = (LPWSTR)KERNEL_LOGGER_NAME;
	// Set the log file mode to real-time and event record callback function
	logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	logFile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(EventRecordCallback);

	// Open the trace for processing the events in real-time 
	std::cout << "Opening trace..." << std::endl;
	TRACEHANDLE hLog = OpenTrace(&logFile);
	if (hLog == (TRACEHANDLE)INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open trace. Error: " << GetLastError() << std::endl;
		free(pSessionProperties);
		return 1;
	}

	Timer timer(500, my_callback);

	timer.start();

	hTrace = hLog;

	// Start a separate thread to process the trace events and avoid blocking the main thread
	std::thread traceThread(processTrace);
	std::cout << "Press Ctrl + C to stop tracing..." << std::endl;
	traceThread.join();

	timer.stop();

	// Stop the kernel logger session after the trace processing
	stopKernelLogger(pSessionProperties);

	// Close the trace handle and free the session properties memory
	CloseTrace(hLog);
	free(pSessionProperties);
	return 0;
}
