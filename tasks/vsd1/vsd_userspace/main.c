/*
 * TODO parse command line arguments and call proper
 * VSD_IOCTL_* using C function 'ioctl' (see man ioctl).
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "cmd.h"
#include "vsd_ioctl.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define DEVICE_NAME "/dev/"MISC_DEVICE_NAME

static int size_get_apply_opts(struct cmd_struct * self, int argc, char ** argv) {
	if (argc > 0) {
		fprintf(stderr, "size_get should provide with no args\n");
		return 1;
	}
	return 0;
}

static void size_get_help(void) {
	fprintf(stderr, "size_t usage : size_get\n");
}

static int size_get_exec(struct cmd_struct *self) {
	vsd_ioctl_get_size_arg_t arg;
	memset(&arg, 0, sizeof(arg));
	printf("get size : ready\n");
	int fd = open(DEVICE_NAME, 0);
	if (fd == -1)
		return 1;
	printf("descriptor opened %d\n", fd);
	int rc = ioctl(fd, VSD_IOCTL_GET_SIZE, &arg);
	close(fd);
	printf("get_size : ioctl finished with err %s\n", strerror(-rc));
	if (!rc) {
		printf("Discovered size %zu\n", arg.size);
	}
	return rc;
}


struct size_set_priv {
	size_t size;
};

static int size_set_apply_opts(struct cmd_struct * self, int argc, char ** argv) {
	if (argc != 1) {
		fprintf(stderr, "size_set : wrong number of args\n");
		return 1;
	}
	char * arg = argv[0], *end_ptr;
	if (!arg) {
		fprintf(stderr, "size_set : wrong param\n");
		return 1;
	}
	errno = 0;
	size_t size = (size_t)strtoull(arg, &end_ptr, 10);
	if (end_ptr != '\0') {
		fprintf(stderr, "size_set : failed to parse param\n");
		return 1;
	}
	struct size_set_priv * priv = (struct size_set_priv *)malloc(sizeof(struct size_set_priv));
	if (!priv) {
		fprintf(stderr, "size_set : failed to parse param\n");
		return 1;
	}
	priv->size = size;
	self->priv = priv;
	return 0;
}

static void size_set_help(void) {
	fprintf(stderr, "size_t usage : size_set [SIZE_IN_BYTES]\n");
}

static int size_set_exec(struct cmd_struct * cmd) {
	vsd_ioctl_set_size_arg_t arg = {
		.size = ((struct size_set_priv * )cmd->priv)->size
	};
	printf("set size : ready\n");
	int fd = open(DEVICE_NAME, 0);
	if (fd == -1)
		return 1;
	printf("descriptor opened %d\n", fd);
	int rc = ioctl(fd, VSD_IOCTL_SET_SIZE, &arg);
	close(fd);
	printf("ioctl finished with err %s\n", strerror(-rc));
	return rc;
}

static struct cmd_struct commands[] = {
	{
		.name = "size_get",
		.apply_opts = size_get_apply_opts,
		.exec = size_get_exec,
		.help = size_get_help
	},
	{
		.name = "size_set",
		.apply_opts = size_set_apply_opts,
		.exec = size_set_exec,
		.help = size_set_help
	}
};

static void help() {
	for(size_t i = 0; i < ARRAY_SIZE(commands); i++) {
		struct cmd_struct * cmd = &commands[i];
		fprintf(stderr, "command : %s => ", cmd->name);
		cmd->help();
	}
}

static struct cmd_struct * find_cmd(char * name) {
	for(size_t i = 0; i < ARRAY_SIZE(commands); i++) {
		struct cmd_struct * cmd = &commands[i];
		if (!strcmp(cmd->name, name))
			return cmd;
	}
	return 0;
}

static int exec_cmd(struct cmd_struct * cmd, int argc, char ** argv) {
	int rc = cmd->apply_opts(cmd, argc, argv);
	if (rc) {
		cmd->help();
		return 1;
	}
	rc = cmd->exec(cmd);
	if (rc)
		return 1;
	return 0;
}

#ifdef IO_QUICK_TST
#include <assert.h>
void tst() {
	int fd = open(DEVICE_NAME, O_RDWR);
	assert(fd != -1);
	assert(lseek(fd, 0, SEEK_SET) == 0);
	int buf[10];
	for(int i = 0; i < 10; i++)
		buf[i] = i;
	int numb = write(fd, &buf, 10 * sizeof(int));
	printf("Numb %d\n", numb);
	assert(numb == 10 * sizeof(int));
	assert(lseek(fd, 0, SEEK_SET) == 0);
	for(int i = 0; i < 10; i++) {
		int tst;
		read(fd, &tst, sizeof(int));
		printf("Try for %d => %d\n", i, tst);
		assert(i == tst);
	}
	close(fd);
}
#endif

int main(int argc, char **argv) {
#ifdef IO_QUICK_TST
	tst();
#endif
	if (argc < 2) {
		fprintf(stderr, "wrong numb of args\n");
		goto fail;
	}
	char * cmd_name = argv[1];
	struct cmd_struct * cmd = find_cmd(cmd_name);
	if (!cmd) {
		fprintf(stderr, "wrong cmd\n");
		goto fail;
	}
	argc -= 2;
	argv += 2;
	int rc = exec_cmd(cmd, argc, argv);
	if (rc)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
fail:
	help();
	return EXIT_FAILURE;
}
