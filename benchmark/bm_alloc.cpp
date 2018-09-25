//
// Created by ycwang on 2018/9/12.
//

#include "benchmark.h"
#include <thread>
#include <condition_variable>

constexpr size_t MEMORY_SIZE = 128 * 1024 * 1024;
constexpr size_t THREAD_COUNT = 4;
constexpr size_t MEMORY_PER_THREAD = MEMORY_SIZE / THREAD_COUNT;
constexpr size_t CHUNK_SIZE = 4 * 1024;
constexpr size_t ALLOC_COUNT = MEMORY_PER_THREAD / CHUNK_SIZE;

std::atomic_int g_state(0);
std::atomic_int g_alloc_end(0);
std::condition_variable g_cv;
std::mutex g_cv_m;
//unsigned g_state = 0;


struct Node
{
	Node* _next;
};

void alloc_common()
{
	while(1 != g_state.load(std::memory_order::memory_order_consume))
		std::this_thread::sleep_for(std::chrono::milliseconds(1));

	printf("start alloc...\n");
	Node *head= nullptr;
	Node *tmp = nullptr;
	for(size_t i=0; i<ALLOC_COUNT; ++i)
	{
		tmp = (Node*)(new char[CHUNK_SIZE]);
		tmp->_next = head;
		head = tmp;
	}

	g_alloc_end.fetch_add(1, std::memory_order_release);
	while(1 != g_state.load(std::memory_order::memory_order_consume))
		std::this_thread::sleep_for(std::chrono::milliseconds(1));

	printf("start release...\n");
	while(head) {
		tmp = head;
		head = head->_next;
		delete [] tmp;
	}
}

void alloc_with_local_heap()
{

}

long long bm_alloc()
{
	constexpr int thread_count  = 4;
	auto alloc = &alloc_common;
	std::thread th1(alloc), th2(alloc), th3(alloc), th4(alloc);
	printf("starting...\n");

	auto t1 = Clock::now();
	g_state.store(1, std::memory_order::memory_order_release);

	while(thread_count != g_alloc_end.load(std::memory_order_consume))
		std::this_thread::sleep_for(std::chrono::milliseconds(1));

	auto t2 = Clock::now();
	auto dt = std::chrono::duration_cast<TimeUnit>(t2 - t1);
	auto total_time = dt.count();
	printf("alloc end, used time: %lld microseconds\n", dt.count());

	t1 = Clock::now();
	g_state.store(2, std::memory_order::memory_order_release);

	th1.join();
	th2.join();
	th3.join();
	th4.join();

	t2 = Clock::now();
	dt = std::chrono::duration_cast<TimeUnit>(t2 - t1);
	total_time += dt.count();
	printf("free end, used time: %lld microseconds\n", dt.count());
	printf("total time: %lld microseconds\n", total_time);

	return dt.count();
}

