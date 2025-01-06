#pragma once

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

class SD
{
	//std::atomic<bool> stopProcessing(false);
	public:
		TRACEHANDLE m_hTrace;
		double m_totalReadBytes;
		double m_totalWriteBytes;
		double m_energy;

	private:
		SD();
		void setHTrace(TRACEHANDLE);
		void setTotalReadBytes(double);
		void setTotalWriteBytes(double);
		void setEnergy(double);
		TRACEHANDLE getHTrace();
		double getTotalReadBytes();
		double getTotalWriteBytes();
		double getEnergy();

		void myCallback();
		double energyCalculation(double);
		void accumulEnergy(double);
};