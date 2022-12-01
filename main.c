/*
 * package string
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/types.h>
#include <fcntl.h>
//#include <getopt.h>
#include <errno.h>


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
void window_resize_handler(int signum);
void term_handler(int signum);
void term_child(int signum);
void reliable_write(int fd, const void *data, size_t size);
int match(const char *reference, const char *buffer, ssize_t bufsize, int state);
void write_pass(int fd);
void write_pass_fd(int srcfd, int dstfd);
int handleoutput(int fd);

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
	int opt_offset = parse_options(argc, (char **) argv);


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
    // note: 为我们的进程创建一个伪终端
    // note: posix_openpt函数提供了一个可移植的方法，以打开一个可用的伪终端主设备。
    masterpt = posix_openpt(O_RDWR); // note: O_RDWR 来自库 fcntl.h O_RDWR:读写打开伪终端主设备
    if (masterpt == -1) {
        perror("无法创建伪终端");
        return RETURN_RUNTIME_ERROR;
    }
    // note: 参考： https://blog.csdn.net/qq_37414405/article/details/83690447
    fcntl(masterpt, F_SETFL, O_NONBLOCK); // note: fcntl函数针对文件描述符提供控制, F_SETFL: 设置文件状态标记， O_NONBLOCK:  非阻塞I/O，如果read(2)调用没有可读取的数据，或者如果write(2)操作将阻塞，则read或write调用将返回-1和EAGAIN错误
    // grantpt()
    // General description
    //
    //The grantpt() function changes the mode and ownership of the slave pseudoterminal device. fildes should be the file
    // descriptor of the corresponding master pseudoterminal. The user ID of the slave is set to the real UID of the
    // calling process and the group ID is set to the group ID associated with the group name specified by the installation
    // in the TTYGROUP() initialization parameter. The permission mode of the slave pseudoterminal is set to readable and
    // writable by the owner, and writable by the group.
    //
    //You can provide secure connections by either using grantpt() and unlockpt(), or by simply issuing the first open
    // against the slave pseudoterminal from the first userid or process that opened the master terminal.
    //Returned value
    //
    //If successful, grantpt() returns 0.
    //If unsuccessful, grantpt() returns -1 and sets errno to one of the following values:
    if (grantpt(masterpt) != 0) { // 授予对从属伪终端设备的访问权限
        perror("无法修改伪终端的权限。");
        return RETURN_RUNTIME_ERROR;
    }

    if (unlockpt(masterpt) != 0) {
        perror("无法解锁为终端。");
        return RETURN_RUNTIME_ERROR;
    }

    ourtty = open("/dev/tty", 0);
    // note: ioctl函数是设备驱动程序中对设备的IO进行管理的函数。
    if (ourtty != -1 && ioctl(ourtty, TIOCGWINSZ, &ttysize) == 0) {
        signal(SIGWINCH, window_resize_handler);
        ioctl(masterpt, TIOCGWINSZ, &ttysize);
    }
    printf("11111111\n");
    // signal.h是C标准函数库中的信号处理部分，定义了程序执行时如何处理不同的信号。信号用作进程间通信，报告异常行为
    // C语言标准定义了6个信号，都定义在signal.h头文件中：
    //
    //(1). SIGABRT：程序异常中止，如调用abort函数。
    //
    //(2). SIGFPE：算术运算出错，如除数为0或溢出。
    //
    //(3). SIGILL：非法函数映像，如非法指令。
    //
    //(4). SIGINT：交互的用户按键请求，如同时按下Ctrl+C键。
    //
    //(5). SIGSEGV：无效内存访问，段错误。
    //
    //(6). SIGTERM：程序的中止请求。

    const char *name = ttyname(masterpt);
    int slavept;
    sigset_t sigmask, sigmask_select;
    sigemptyset(&sigmask_select); // sigemptyset: 从集合中清空所有信号
    sigaddset(&sigmask, SIGCHLD); // sigaddset: 从集合中添加信号
    sigaddset(&sigmask, SIGHUP); // hangup
    sigaddset(&sigmask, SIGTERM);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGTSTP);
    sigprocmask(SIG_SETMASK, &sigmask, NULL); // sigprocmask: 检查和更改阻塞的信号
    signal(SIGHUP, term_handler); // signal: 该函数设置一个函数(回调函数)来处理捕获到异常信号时需要执行的操作
    signal(SIGTERM, term_handler);
    signal(SIGINT, term_handler);
    signal(SIGTSTP, term_handler);
    printf("222222222222222222\n");
    childpid = fork();
    // 在Linux下有两个基本的系统调用可以用于创建子进程：fork()和vfork()，当一个进程正在运行的时候，使用了fork()函数之后就会创建另一个进程。
    // 与一般函数不同的是，fork()函数会有两次返回值，一次返回给父进程（该返回值是子进程的PID（Process ID）），第二次返回是给子进程，其返回值为0.
    // 所以在调用该函数以后，我们需要通过返回值来判断当前的代码时父进程还是子进程在运行：
    //
    //    返回值大于0 -> 父进程在运行
    //    返回值等于0 -> 子进程在运行
    //    返回值小于0 -> 函数系统调用出错
    //
    //通常系统调用出错的原因有两个：①已存在的系统进程已经太多；②该实际用户ID的进程总数已经超过了限制。

    if (childpid == 0) {
        // 子进程
        printf("3333333333333333333333333\n");
        sigprocmask(SIG_SETMASK, &sigmask_select, NULL);
        setsid(); // 重新创建一个session，子进程从父进程继承了SessionID、进程组ID和打开的终端，子进程如果要脱离父进程，不受父进程的控制，我们可以使用这个setsid命令。
        // setsid()调用成功后，返回新的会话的ID，调用setsid函数的进程成为新的会话的领头进程，并与其父进程的会话组和进程组脱离。由于会话对控制终端的独占性，进程同时与控制终端脱离。
        slavept = open(name, O_RDWR);
#ifdef TIOCSCTTY
        if (ioctl(slavept, TIOCSCTTY) == -1) {
            perror("csshpass: 在子进程中设置控制终端失败。");
            exit(RETURN_RUNTIME_ERROR);
        }
#endif
        close(slavept);
        close(masterpt);
        char **new_argv=malloc(sizeof(char *)*(argc+1));
        int i;
        for (i=0;i<argc;++i) {
            new_argv[i] = argv[i];
        }
        new_argv[i] = NULL;
        printf("1234\n");
        execvp(new_argv[0], new_argv); // execvp()会从环境变量所指的目录中查找符合参数 file 的文件名, 找到后执行该文件, 然后将第二个参数argv 传给该执行的文件。
        // execvp: 执行命令
        perror("CSSHPASS: Faild to run command.");
        exit(RETURN_RUNTIME_ERROR);
    } else if (childpid < 0) {
        perror("CSSHPASS: Faild to create child process");
        return RETURN_RUNTIME_ERROR;
    }
    slavept = open(name, O_RDWR|O_NOCTTY);
    printf("5555555555555555555555\n");
    int status = 0;
    int terminate = 0;
    pid_t wait_id;
    do {
        if (!terminate) {
            fd_set readfd; // 存放文件描述符的集合
            FD_ZERO(&readfd); // 清空集合
            FD_SET(masterpt, &readfd); // 将文件描述符添加到集合中
            int selret = pselect(masterpt+1, &readfd, NULL, NULL, NULL, &sigmask_select);
            // 下面判断是什么作用？
            if (termsig!=0) {
                int signum = termsig;
                termsig = 0;
                term_child(signum);
                continue;
            }
            if (select > 0) {
                if (FD_ISSET(masterpt, &readfd)) {
                    int ret;
                    if ((ret = handleoutput(masterpt))) {
                        if (ret > 0) {
                            close(masterpt);
                            close(slavept);
                        }
                        terminate = ret;
                        if (terminate) {
                            close(slavept);
                        }
                    }
                }
            }
            wait_id=waitpid(childpid, &status, WNOHANG); // WNOHANG: return immediately if no child has exited.
        } else {
            wait_id=waitpid(childpid, &status, 0);
        }
    } while(wait_id==0 || (!WIFEXITED(status) && !WIFSIGNALED(status)));
    if (terminate > 0) {
        return  terminate;
    } else if (WIFEXITED(status)){
        return WEXITSTATUS(status);
    } else {
        return 255;
    }
}

// note: 不做任何事情，只是确保当信号到达时可以正常终止
void sigchld_handler(int signum) {}

void window_resize_handler(int signum) {
    struct winsize ttysize;
    if(ioctl(ourtty, TIOCGWINSZ, &ttysize) == 0) {
        ioctl(masterpt, TIOCGWINSZ, &ttysize);
    }
}

void term_handler(int signum) {
    termsig = signum;
}

void term_child(int signum) {
    fflush(stdout);
    switch(signum) {
        case SIGINT:
            reliable_write(masterpt, "\x03", 1);
            break;
        case SIGTSTP:
            reliable_write(masterpt, "\x1a", 1);
            break;
        default:
            if(childpid>0) {
                kill(childpid, signum);
            }
    }
}

void reliable_write(int fd, const void *data, size_t size) {
    ssize_t result = write(fd, data, size);
    if (result != size) {
        if (result < 0) {
            perror("CSSHPASS: write failed.");
        } else {
            fprintf(stderr, "CSSHPASS: Short write. Tried to write %lu, only write %ld\n", size, result);
        }
    }
}

int handleoutput(int fd) {
    static int prevmatch = 0;
    static int state1, state2, state3;
    static int firsttime = 1;
    static const char *compare1=PASSWORD_PROMPT;
    static const char compare2[] = "The authenticity of host ";
    static const char compare3[] = "differs from the key for the IP address";
    char buffer[256];
    int ret = 0;
    if (args.pwprompt) {
        compare1 = args.pwprompt;
    }

    if (args.verbose && firsttime) {
        firsttime = 0;
        fprintf(stderr, "CSSHPASS: searching for password prompt using match \"%s\"\n", compare1);
    }

    int numread = read(fd, buffer, sizeof(buffer)-1);
    buffer[numread] = '\0';
    if (args.verbose) {
        fprintf(stderr, "CSSHPASS: read %s\n", buffer);
    }
    state1 = match(compare1, buffer, numread, state1);
    if (compare1[state1] == '\0') {
        if (!prevmatch) {
            if(args.verbose) {
                fprintf(stderr, "CSSHPASS: detected prompt. Sending password.\n");
            }
            write_pass(fd);
            state1 = 0;
            prevmatch = 1;
        } else {
            if (args.verbose) {
                fprintf(stderr, "CSSHPASS: detected prompt, again. Wrong password. Terminating.\n");
                ret = RETURN_INCORRECT_PASSWORD;
            }
        }
    }
    if (ret == 0) {
        state2 = match(compare2, buffer, numread, state2);
        if (compare2[state2] == '\0') {
            if (args.verbose) {
                fprintf(stderr, "CSSHPASS: detected host authentication prompt. Exiting.\n");
                ret = RETURN_HOST_KEY_UNKNOWN;
            }
        } else {
            state3 = match(compare3, buffer, numread, state3);
            if (compare3[state3] == '\0') {
                ret = RETURN_HOST_KEY_CHANGED;
            }
        }
    }
    return ret;
}

int match(const char *reference, const char *buffer, ssize_t bufsize, int state) {
    int i;
    for (i=0;reference[state] != 0 && i < bufsize; ++i) {
        if(reference[state] == buffer[i]) {
            state++;
        } else {
            state = 0;
            if (reference[state] == buffer[i]) {
                state++;
            }
        }
    }
    return state;
}

void write_pass(int fd) {
    switch(args.pwtype) {
        case PWT_STDIN:
            write_pass_fd(STDIN_FILENO, fd);
            break;
        case PWT_FD:
            write_pass_fd(args.pwsrc.fd, fd);
            break;
        case PWT_FILE:
        {
            int srcfd = open(args.pwsrc.filename, O_RDONLY);
            if (srcfd != -1) {
                write_pass_fd(srcfd, fd);
                close(srcfd);
            } else {
                fprintf(stderr, "CSSHPASS: Failed to open password file \"%s\": %s\n", args.pwsrc.filename, strerror(errno));
            }
        }
            break;
        case PWT_PASS:
            reliable_write(fd, args.pwsrc.password, strlen(args.pwsrc.password));
            reliable_write(fd, "\n", 1);
            break;
    }
}

void write_pass_fd(int srcfd, int dstfd) {
    int done = 0;
    while( !done ) {
        char buffer[40];
        int i;
        int numread = read(srcfd, buffer, sizeof(buffer));
        done = (numread<1);
        for (i=0; i<numread && !done; ++i) {
            if (buffer[i] != '\n') {
                reliable_write(dstfd, buffer+1, 1);
            } else {
                done=1;
            }
        }
    }
    reliable_write(dstfd, "\n", 1);
}