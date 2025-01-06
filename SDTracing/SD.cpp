#include "SD.h"

SD::SD()
{
	this->setHTrace(0);
	this->setTotalReadBytes(0);
	this->setTotalWriteBytes(0);
	this->setEnergy(0);
}

void SD::setHTrace(TRACEHANDLE hTrace)
{
	this->m_hTrace = hTrace;
}

void SD::setTotalReadBytes(double totalReadBytes)
{
	this->m_totalReadBytes == totalReadBytes;
}

void SD::setTotalWriteBytes(double totalWriteBytes)
{
	this->m_totalWriteBytes == totalWriteBytes;
}

void SD::setEnergy(double energy)
{
	this->m_energy == energy;
}

TRACEHANDLE SD::getHTrace()
{
	return this->m_hTrace;
}

double SD::getTotalReadBytes()
{
	return this->m_totalReadBytes;
}

double SD::getTotalWriteBytes()
{
	return this->m_totalWriteBytes;
}

double SD::getEnergy()
{
	return this->m_energy;
}

void SD::accumulEnergy(double energy)
{
	this->m_energy += energy;
}

double SD::energyCalculation(double interval_ms) {
	std::cout << "Calculating energy..." << std::endl;
	double total_energy = 0;

	double interval_s = interval_ms / 1000;

	long read_rate = this->getTotalReadBytes() / interval_s;
	long write_rate = this->getTotalWriteBytes() / interval_s;

	double read_power = 2.2 * (double)read_rate / 5600000000;
	double write_power = 2.2 * (double)write_rate / 5300000000;

	double avg_power = read_power + write_power;

	double interval_energy = avg_power * interval_s;

	total_energy += interval_energy;

	std::cout << "Total energy: " << total_energy << std::endl;

	return total_energy;
}

void SD::myCallback()
{
	std::cout << "Callback called" << std::endl;
	std::cout << "Total read bytes: " << this->getTotalReadBytes() << std::endl;
	std::cout << "Total write bytes: " << this->getTotalWriteBytes() << std::endl;
	std::future<double> energy_future = std::async(std::launch::async, &SD::energyCalculation, this, 500);

	this->setTotalReadBytes(0);
	this->setTotalWriteBytes(0);

	this->accumulEnergy(energy_future.get());
	std::cout << "Energy: " << this->getEnergy() << std::endl;
}