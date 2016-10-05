struct cmd_struct {
	int (*apply_opts)(struct cmd_struct * self, int argc, char ** argv);
	void (*help)(void);
	int (*exec)(struct cmd_struct * self);
	const char * name;
	void * priv;
};
