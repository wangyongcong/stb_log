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

struct Node
{
	Node* _next;
};

void alloc_common()
{
	while(1 != g_state.load(std::memory_order::memory_order_consume))
		std::this_thread::sleep_for(std::chrono::milliseconds(1));

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

	while(head) {
		tmp = head;
		head = head->_next;
		delete [] tmp;
	}
}

void alloc_with_local_heap()
{
	while(1 != g_state.load(std::memory_order::memory_order_consume))
		std::this_thread::sleep_for(std::chrono::milliseconds(1));

	Node *head = nullptr;
	Node *tmp = nullptr;
	char *buf = new char[CHUNK_SIZE * ALLOC_COUNT];
	char *chunk = buf;
	for(size_t i=0; i<ALLOC_COUNT; ++i, chunk += CHUNK_SIZE)
	{
		tmp = (Node*)chunk;
		tmp->_next = head;
		head = tmp;
	}

	g_alloc_end.fetch_add(1, std::memory_order_release);
	while(1 != g_state.load(std::memory_order::memory_order_consume))
		std::this_thread::sleep_for(std::chrono::milliseconds(1));

	delete [] buf;
}

long long bm_alloc()
{
	constexpr int thread_count  = 4;
//	auto alloc = &alloc_common;
	auto alloc = &alloc_with_local_heap;
	std::thread th1(alloc), th2(alloc), th3(alloc), th4(alloc);
	printf("thread: %lu, chunk: %lu, count: %lu, total: %lu\n", THREAD_COUNT, CHUNK_SIZE, ALLOC_COUNT, CHUNK_SIZE * ALLOC_COUNT);

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

/*
 * [alloc_common]
 *   alloc end, used time: 21546 microseconds
 *   free end, used time: 21375 microseconds
 *   total time: 42921 microseconds
 *
 *   alloc end, used time: 24894 microseconds
 *   free end, used time: 23388 microseconds
 *   total time: 48282 microseconds
 *
 * [alloc_with_local_heap]
 *   alloc end, used time: 22980 microseconds
 *   free end, used time: 4788 microseconds
 *   total time: 27768 microseconds
 *
 *   alloc end, used time: 21625 microseconds
 *   free end, used time: 4005 microseconds
 *   total time: 25630 microseconds
 *
 * result:
 *   allocation is almost same. operation new may alloc memory from thread local heap with no competition.
 *   free a big chunk is more faster than multiple free of small chunks
 * */
