#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#include <getopt.h>

// 定义默认的sshpass环境变量名称 SSHPASS
#define DEFAULT_ENV_PASSWORD "SSHPASS"
// 定义并初始化了一个结构体实例
// 全局结构体
struct {
	enum {
        PWT_STDIN, // 标准输入
        PWT_FILE, // 文件
        PWT_FD, // todo: ??? 哪个是SSHPASS环境变量提供密码的类型
        PWT_PASS // todo: ???
    } pwtype; // note: 密码来源的类型
	union {
		const char *filename;
		int fd;
		const char *password;
	} pwsrc;
	const char *pwprompt;
	int verbose;
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
int parse_options(int argc, char *argv);


int main(int argc, char *argv[]) {
	// 解析参数
	int opt_offset = parse_options(argc, (char *) argv);

    printf("Hello, World!\n");
    return 0;
}

int parse_options(int argc, char *argv) {
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
            case 'V':
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
                    fprintf(stderr, "csshpass: -e option given but \"\s\" environment variable is not set.\n", optarg);
                    error=RETURN_INVALID_ARGUMENTS;
                }
                hide_password(); // todo: ???
                unsetenv(optarg); // note: 从环境变量中移除名字为SSHPASS的变量
        }
    }


    }