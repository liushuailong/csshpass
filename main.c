/*
 * package string
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <signal.h>
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#include <sys/select.h>
#include <fcntl.h>
//#include <getopt.h>

// 定义默认的sshpass环境变量名称 SSHPASS
#define DEFAULT_ENV_PASSWORD "SSHPASS"
#define PACKAGE_STRING "csshpass package 2022 learn for test"
#define PASSWORD_PROMPT "password prompt"
#define PACKAGE_NAME "csshpass"

#ifndef HAVE_POSIX_OPENPT
int posix_openpt(int flags) {
    return open("/dev/ptmx", flags);
}
#endif

static int ourtty;
static int masterpt;

int childpid;
int termsig;

// 定义并初始化了一个结构体实例
// 全局结构体
struct {
	enum {
        PWT_STDIN, // 标准输入
        PWT_FILE, // 文件
        PWT_FD, // 文件描述符
        PWT_PASS // SSHPASS环境变量提供密码的类型
    } pwtype; // note: 密码来源的类型
	union {
		const char *filename;
		int fd;
		const char *password;
	} pwsrc;
	const char *pwprompt;
	int verbose; // todo: 这个字段是干什么的？
	char *orig_password;
} args;

// 定义函数返回枚举类型
enum program_return_codes {
    RETURN_NOERROR,
    RETURN_INVALID_ARGUMENTS,
    RETURN_CONFLICTING_ARGUMENTS,
    RETURN_RUNTIME_ERROR,
    RETURN_PARSE_ERRROR,
    RETURN_INCORRECT_PASSWORD,
    RETURN_HOST_KEY_UNKNOWN,
    RETURN_HOST_KEY_CHANGED,
};

// c语言编译是按顺序的，函数在使用前需要定义或者申明
int parse_options(int argc, char *argv[]);
static void hide_password();
static void show_help();
int run_program(int argc, char *argv[]);
void sigchld_handler(int signum);

static void show_help() {
    // fixme: 有没有更好的字符串格式化方法
    printf("Usage: " PACKAGE_NAME " [-f|-d|-p|-e] [-hV] Command parameters\n"
                                  "    -f filename Take password to use from file\n"
                                  "    -d number   Use Number as file descriptor for getting password\n"
                                  "    -e          Password is passed as env-var \"SSHPASS\"\n"
                                  "    With no parameters - password will be taken from stdin\n\n"
                                  "    -P prompt   Which string should sshpass search for to detect a password prompt\n"
                                  "    -v          Be verbose about what you're dong\n"
                                  "    -h          Show help (this screen)\n"
                                  "    -V          Print version information\n"
                                  "At most one of -f, -d, -p or -e should be used\n"
    );
}

int main(int argc, char *argv[]) {
	// 解析参数
	int opt_offset = parse_options(argc, (char *) argv);


    // note: 当 opt_offset 小于 0 时 opt_offset 代表的是错误的代号
    // note: 处理函数输入参数错误
    if (opt_offset < 0) {
        fprintf(stderr, "Use \"csshpass -h\" to get help\n");
        return -(opt_offset + 1); // note: 原文注释的 -1 --> 0, -2 --> 1, 这又代表什么意思？ 这个值代表的是返回的类型，和枚举 program_return_codes 对应
    }

    // note: 当 opt_offset 等于 0 时
    if (opt_offset < 1) {
        show_help();
        return 0;
    }

    if (args.orig_password != NULL) {
        hide_password();
    }

    return run_program(argc-opt_offset, argv+opt_offset); // todo: 注意参数
}

int parse_options(int argc, char *argv[]) {
	int error = -1; // 错误返回值
	int opt;

	// args是一个全局结构体
	// 设置默认的密码来源是标准输入
	args.pwtype=PWT_STDIN;
	args.pwsrc.fd=0;
// 定义 VIRGIN_PWTYPE 宏，用于检测密码来源冲突
// sshpass密码填充方式有三种，通过-p后边的参数将密码传送过去，读取文件第一行作为密码传过去，或者通过-e将名字为SSHPASS的环境变量作为密码传过去。
#define VIRGIN_PWTYPE if(args.pwtype!=PWT_STDIN) {fprintf(stderr, "Conflicting password source\n"); error=RETURN_CONFLICTING_ARGUMENTS;}
    while( (opt=getopt(argc, argv, "+f:d:p:P:he::Vv")) != -1 && error == -1) {
        switch ( opt ) {
            case 'f': // note: 密码来源一个文件
                VIRGIN_PWTYPE; // note: 检测密码的类型是否是标准输入，如果是输出密码来源冲突错误
                args.pwtype = PWT_FILE;
                args.pwsrc.filename = optarg; // note: unistd.h 库中定义的一个变量，保存的是对应选项的值
                break;

            case 'd': // note: 密码来源一个文件描述符
                VIRGIN_PWTYPE;
                args.pwtype = PWT_FD;
                args.pwsrc.fd = atoi(optarg); // note: atoi将字符串转化成整形数;
                break;
            case 'p': // note: 密码来源于命令行
                VIRGIN_PWTYPE;
                args.pwtype = PWT_PASS;
                args.orig_password = optarg;
                break;
            case 'P':
                args.pwprompt = optarg;
                break;
            case 'v':
                args.verbose++;
                break;
            case 'e':
                VIRGIN_PWTYPE;
                args.pwtype = PWT_PASS;
                if (optarg == NULL) {
                    optarg = "SSHPASS";
                }
                args.orig_password = getenv(optarg); // note: 从环境变量中获取变量名为SSHPASS的值，如果没有则返回NULL
                if (args.orig_password == NULL) {
                    fprintf(stderr, "csshpass: -e option given but \"%s\" environment variable is not set.\n", optarg);
                    error=RETURN_INVALID_ARGUMENTS;
                }
                hide_password(); // note: ??? 将 orig_password 中的密码复制给 pwsrc，并将 orig_password 置为空；
                unsetenv(optarg); // note: 从环境变量中移除名字为SSHPASS的变量
                break;
            case '?':
            case ':':
                error = RETURN_INVALID_ARGUMENTS;
                break;
            case 'h':
                error = RETURN_NOERROR;
                break;
            case 'V': // note: 打印版本信息
                printf("%s\n"
                       "(C) 2022 sshpass copy\n"
                       "Using \"%s\" as the default password prompt indicator.\n",
                       PACKAGE_STRING, PASSWORD_PROMPT); // todo: ???
                exit(0);
        }
    }

    // note: 这个函数返回代表错误类型的数字或者代表下一次调用getopt函数时返回参数在argv中的下标
    if (error >= 0) {
        return -(error + 1); // note: 将错误的返回值转化后返回主函数
    } else {
        return optind; // note: 这个值代表的是什么意思？？？ 下一次调用 getopt 时，从 optind 存储的位置处重新开始检查选项, 那也就是说getopt函数的输入类型都是在argv数组前面的。
    }
}

static void hide_password() {
    assert(args.pwsrc.password == NULL); // note: 判断password不为空
    args.pwsrc.password = strdup(args.orig_password); // note: string.h 库中的函数 复制字符串
    // note: 下面这个while的作用是什么？ origin_password是一个指向字符串类型的指针，下面的while循环是将orig_password指向的字符串的每一位都置空。
    // todo: 那问题来了，为什么要置空？
    while(*args.orig_password != '\0') {
        *args.orig_password = '\0';
        ++args.orig_password;
    }
    args.orig_password = NULL; // note: 将args的orig_password置为空
}

int run_program(int argc, char *argv[]) {
    struct winsize ttysize; // note: struct winsize for lib sys/ioctl.h
    signal( SIGCHLD, sigchld_handler ); // note: signal 函数来自库 signal.h
    masterpt = posix_openpt(O_RDWR); // note: O_RDWR 来自库 fcntl.h

    

}

// note: 不做任何事情，只是确保当信号到达时可以正常终止
void sigchld_handler(int signum) {}
