#include <cstdio>

extern long long bm_stb_latence();
extern long long bm_stb_log();
extern long long bm_nanolog();

int main(int argv, char *args[])
{
	bm_stb_latence();
	//bm_stb_log();
	//bm_nanolog();
	getchar();
	return 0;
}
