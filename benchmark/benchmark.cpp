#include <cstdio>

extern long long bm_stb_log();
extern long long bm_nanolog();
extern long long bm_alloc();

int main(int argv, char *args[])
{
	long long dt = 0;
	dt = bm_stb_log();
//	dt = bm_nanolog();
//	bm_alloc();
	printf("END time used: %lld microseconds", dt);
//	getchar();
	return 0;
}
