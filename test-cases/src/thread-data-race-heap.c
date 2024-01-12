#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <pthread.h>

//#define ENABLE_MUTEX
//#define ENABLE_RWLOCK


int money = 1000000;
char apple = 80;
int banana = 50;

pthread_mutex_t gMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
//std::mutex gMutex_cpp;



void buy_banana(void *arg)
{
	int i = (int)arg;
	printf("thread1 i addr = %08x\n", &i);

	int *money = (unsigned int*)arg;
	printf("thread1 arg address = %0lx\n", arg);
	printf("thread1 money = %d\n", money);
        while(*money > banana){
#ifdef	ENABLE_MUTEX
		pthread_mutex_lock(&gMutex);    // 加锁
#endif
#ifdef  ENABLE_RWLOCK
                pthread_rwlock_wrlock(&rwlock);    // 加锁
#endif
                sleep(0);
		*money -= banana;
#ifdef  ENABLE_MUTEX
		pthread_mutex_unlock(&gMutex);  // 解锁
#endif
#ifdef  ENABLE_RWLOCK
                pthread_rwlock_unlock(&rwlock);    // 加锁
#endif
        }
}


void buy_apple(void *arg)
{
	int i = (int)arg;
	printf("thread2 i addr = %08x\n", &i);

	int *money = (unsigned int*)arg;
	printf("thread2 arg address = %0lx\n", arg);
	printf("thread2 money = %d\n", money);
	while(*money > apple){
#ifdef  ENABLE_MUTEX
                pthread_mutex_lock(&gMutex);    // 加锁
#endif
#ifdef  ENABLE_RWLOCK
                pthread_rwlock_wrlock(&rwlock);    // 加锁
#endif
                sleep(0);
                *money -= apple;
#ifdef  ENABLE_MUTEX
                pthread_mutex_unlock(&gMutex);  // 解锁
#endif
#ifdef  ENABLE_RWLOCK
                pthread_rwlock_unlock(&rwlock);    // 加锁
#endif
	}
}

int main(int argc, char *argv[])
{
	unsigned int *a = (unsigned int *)malloc(1024);
	printf("malloc address = %0lx\n", a);
	a[0] = 100000;
	printf("a = %d\n", a[0]);
	printf("apple address = %0lx\n", &apple);
	printf("banana address = %0lx\n", &banana);

	pthread_t thread1, thread2;

	pthread_create(&thread1, NULL, buy_banana, a);
	pthread_create(&thread2, NULL, buy_apple, a);

	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);

	free(a);
	//sleep(100);
	return 0;
}
