#include <stdio.h>

// 定义并初始化了一个结构体实例
// 全局结构体
struct {
	enum { PWT_STDIN, PWT_FILE, PWT_FD, PWT_PASS } pwtype;
	union {
		const char *filename;
		int fd;
		const char *password;
	} pwsrc;
	const char *pwprompt;
	int verbose;
	char *orig_password;
} args;

int parse_options(int argc, char *argv);


int main(int argc, char *argv[]) {
	// 解析参数
	int opt_offset = parse_options(argc, argv);

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

}
