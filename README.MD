# csshpass
[TOC]
## 背景
工作中经常会连接到服务器工作，为了简化连接，使用sshpass应用，可以避免交互验证。
可以使用程序和容易的在服务器之间传递文件。sshpass应用只有500行代码，可以通过
对该应用的复现，加强自己c语言的编成能力和对sshpass实现流程的理解，为下一步使用
rust实现sshpass功能打下基础，具体实现将会在ccc项目中完成。

## sshpass解读


## c语言知识点

### 向程序传递参数
args: 参数的个数
argv： 参数组成的数组
```c
int main(int args, char *argv[]) {}
```

### 解析命令行传递的参数
```c
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    int flags, opt;
    int nsecs, tfnd;

    nsecs = 0;
    tfnd = 0;
    flags = 0;
    while ((opt = getopt(argc, argv, "nt:")) != -1) {
        switch (opt) {
        case 'n':
            flags = 1;
            break;
        case 't':
            nsecs = atoi(optarg);
            tfnd = 1;
            break;
        default: /* '?' */
            fprintf(stderr, "Usage: %s [-t nsecs] [-n] name\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    printf("flags=%d; tfnd=%d; nsecs=%d; optind=%d\n",
            flags, tfnd, nsecs, optind);

    if (optind >= argc) {
        fprintf(stderr, "Expected argument after options\n");
        exit(EXIT_FAILURE);
    }

    printf("name argument = %s\n", argv[optind]);

    /* Other code omitted */

    exit(EXIT_SUCCESS);
}

```

### 向终端打印字符串

```c
int main(int args, char *argv[]) {
    printf("hello world!\n"); // 注意打印的字符输出到终端不会自动换行
    return 0;
}
```

### 字符串格式化
参考：https://www.runoob.com/cprogramming/c-function-printf.html
```c
int main(int args, char *argv[]) {
    char cstr[] = "hello world!\n";
    printf("%s", cstr);
    return 0;
}
```

### 数据结构和定义
int/char/
#### 整数
```c
int main(int args, char *argv[]) {
    int num = 10; // 整型数据
    printf("%d", num);
    return 0;
}
```

#### 浮点型数据
```c
int main(int args, char *argv[]) {
    float f = 0;
    double d = 0;
    printf("%f", f);
    print("%d", d);
} 
```
#### 字符与字符串
字符是从语言的基本数据类型，使用单引号；  
在 C 语言中，字符串实际上是使用空字符 \0 结尾的一维字符数组。因此，\0 是用于标记字符串的结束。

```c
int main(int args, char *argv[]) {
    char cchar = 'a'; // 字符
    char cstr[] = "a"; // 字符串
    char site[7] = {'R', 'U', 'N', 'O', 'O', 'B', '\0'};
    // or
    char site[] = "RUNOOB";
    printf("site is %s", site);
    return 0;
}
```

#### 数组
C 语言支持数组数据结构，它可以存储一个固定大小的相同类型元素的顺序集合。
```c
int main(int args, char *argv[]) {
    int arr3_int[4] = {1, 2, 3, 4};
    int arr_int[] = {1, 2, 3, 4}; 
    int arr2_int[10] = 50;
    // 获取数组长度
    printf("%lu", sizeof(arr2_int) / sizeof(arr2_int[0]));
}
```
#### 结构体
```c
struct point {
    int x;
    int y;
};

struct point a; // 定义一个struct point类型的变量;
typedef struct point Point; // 给类型起别名；
Point a; // 定义一个Point类型的变量；
```

#### 枚举类型
c语言中的一种基本数据类型
没有指定值的枚举元素，其值为前一元素加 1
```c
enum season {
    spring, // 0
    summer=3, // 3
    autumn, // 4
    winter  // 5
};
```

#### c指针
每一个变量都有一个内存位置，每一个内存位置都定义了可使用 & 运算符访问的地址，它表示了在内存中的一个地址。  
指针也就是内存地址，指针变量是用来存放内存地址的变量。  
在变量声明的时候，如果没有确切的地址可以赋值，为指针变量赋一个 NULL 值是一个良好的编程习惯。
```c
int main(int args, char *argv[]) {
    int num = 5;
    int *p; // 定义指针变量
    p = &num;
    printf("num 变量的地址： %p\n", p);
    printf("p 指针指向的值: %d", *p);
    return 0
}
```

#### 共用体
共用体是一种特殊的数据类型，允许您在相同的内存位置存储不同的数据类型。
为了访问共用体的成员，我们使用成员访问运算符（.）。
在同一时间只能保存一种成员类型的变量。
```c
#include <stdio.h>
#include <string.h>

union Data {
    int i;
    float f;
    char str[20];
};
int main(int args, char *argv[]) {
    union Data data;
    printf("Memory size occupied by data: %d/n", sizeof(data));
    data.i = 10;
    printf( "data.i : %d\n", data.i);
    data.f = 220.5;
    printf( "data.f : %f\n", data.f);
    strcpy( data.str, "C Programming"); // ?
    printf( "data.str : %s\n", data.str);
}
```

### 结构跳转

#### 循环语句
在c语言中只使用以下两种循环，do...while循环不使用  
循环控制：break/continue  
不要使用goto语句  

```c
// while 循环
#include <stdio.h>
int main(int args, char *argv[]) {
    int num  = 10;
    while (num > 0) {
        printf("num: %d\n", num);
        num -= 1; // 统一一律不使用自增自减运算符
    }
    return 0;
}
```

```c
// for 循环
#include <stdio.h>
int main(int args, char *argv[]) {
    for (int i = 0; i <= 10; i +=1) {
        printf("i = %d\n", i);
    }
    return 0;
}

```

### 如何使用gcc编译源代码
```bash
# 编译单文件程序
gcc test.c -o test
```

### 宏编成
#### #define
宏定义必须在一行
```c
#define TEST_VALUE 1
```

#### #ifdef
条件编译
```c
#ifdef TEST_VALUE 
#define TEST_VALUE 1
// 条件编译, 如果在当前环境中已经定义过TEST_VALUE则跳过编译当前代码块，否则编译当前代码块
#endif
```


### 统一C和Rust的编成风格，以Rust为主

### stdio.h 标准库的学习

### fcntl.h 标准库的学习
#### fcntl函数
针对文件描述符提供控制
fcntl函数有5种功能：
1. 复制一个现有的描述符(cmd=F_DUPFD).
2. 获得／设置文件描述符标记(cmd=F_GETFD或F_SETFD).
3. 获得／设置文件状态标记(cmd=F_GETFL或F_SETFL).
4. 获得／设置异步I/O所有权(cmd=F_GETOWN或F_SETOWN).
5. 获得／设置记录锁(cmd=F_GETLK , F_SETLK或F_SETLKW).

#### execvp函数
在程序中执行数组中的命令来执行。
```text
int execvp(const char *file, char * const argv []);
execvp()会从环境变量所指的目录中查找符合参数 file 的文件名, 找到后执行该文件, 然后将第二个参数argv 传给该执行的文件。
如果执行成功则函数不会返回, 执行失败则直接返回-1。
```
test.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
void main(int argc, char *argv[]) {
	char **new_argv=malloc(sizeof(char *)*(argc));
    int i;
    for (i=0;i<argc-1;++i) {
        new_argv[i] = argv[i + 1];
    }
    new_argv[i] = NULL;
	pid_t pid = fork();
	if (pid == 0){
		execvp(new_argv[0], new_argv);
		exit(1);
	} else {
		wait(pid);
	}
}
```
```bash
>>>./test.out ls -rlt
总用量 24
-rw-r--r-- 1 slliu slliu   402 11月 29 11:32 test.c
-rwxr-xr-x 1 slliu slliu 16808 11月 29 11:33 a.out
```
