#include <cstdio>

extern long long bm_stb_log();
extern long long bm_nanolog();
extern long long bm_alloc();

/* 
send 20000 messages
  stb_log: 2700 microseconds
  nano_log: 4200 microseconds
*/
int main(int argv, char *args[])
{
	long long dt = 0;
	dt = bm_stb_log();
	// dt = bm_nanolog();
	printf("END time used: %lld microseconds", dt);
//	getchar();
	return 0;
}
