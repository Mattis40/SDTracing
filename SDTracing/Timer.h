#pragma once

#include <ctime>
#include <thread>
#include <functional>
#include <atomic>

class Timer
{
public:
	Timer(int interval, std::function<void()> callback);
	~Timer();
	void start();
	void stop();
	bool is_running();

private:
	int interval;
	time_t start_time;
	time_t end_time;
	std::thread timer_thread;
	std::function<void()> callback;
	std::atomic<bool> running;
};

