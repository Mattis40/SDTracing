#include "Timer.h"
#include <thread>
#include <chrono>
#include <functional>
#include <atomic>

//
// Timer.cpp
//
Timer::Timer(int interval, std::function<void()> callback)
    : interval(interval), running(false), callback(callback)
{
}

Timer::~Timer()
{
    stop();
}

void Timer::start()
{
    if (running)
        return;

    running = true;
    timer_thread = std::thread([this]() {
        while (running) {
			std::this_thread::sleep_for(std::chrono::milliseconds(interval));
			if (running && callback)
			{
				callback();
			}
        }
		});
}

void Timer::stop()
{
    running = false;
    if (timer_thread.joinable())
    {
        timer_thread.join();
    }
}

bool Timer::is_running()
{
    return running;
}
