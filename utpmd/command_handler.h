#ifndef COMMAND_HANDLER
#define COMMAND_HANDLER

#include "stuff_inoutbuf.h"

int handle_command(unsigned char *in, int in_size, unsigned char *out, int *out_size);

int setup_error(unsigned char *out, int *out_size, int errcode);

#endif   /*   COMMAND_HANDLER   */
