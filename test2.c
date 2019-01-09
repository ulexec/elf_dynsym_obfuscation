#include <stdio.h>
#include <pthread.h>
#include <elf.h>
#include <unistd.h>

int main(void)
{
        pthread_attr_t attr;
	FILE *fd = fopen("/etc/passwd", "r");
	printf("Hi\n");
	pthread_attr_init(&attr);
	pause();
}

