#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "common/common.h"
#include "common/fs_defs.h"
#include "dynamic_libs/fs_functions.h"
#include "dynamic_libs/os_functions.h"
#include "kernel/kernel_functions.h"
#include "utils/logger.h"
#include "function_hooks.h"

#define LIB_CODE_RW_BASE_OFFSET                         0xC1000000
#define CODE_RW_BASE_OFFSET                             0x00000000

#define USE_EXTRA_LOG_FUNCTIONS   0

#define MASK_FD 0x0fff00ff
#define MAX_CLIENT 32

/* *****************************************************************************
 * From my understanding, BSS is an area of memory where uninitialized variables
 * that don't yet have any value associated are stored.
 * Since the system functions already create these, we can make a layout of a
 * few of the existing ones.
 * ****************************************************************************/
struct bss_t {
	int socket_fsa[MAX_CLIENT];
	void *pClient_fs[MAX_CLIENT];
	int socket_fs[MAX_CLIENT];
	volatile int lock;
};

// This reads a pointer from 0x100000e4 to those variables
#define bss_ptr (*(struct bss_t **)0x100000e4)

// Dereferences that pointer
#define bss (*bss_ptr)
// Now we can do stuff like bss.socket_fs[2]

// Finds a slot for a client.
static int client_num_alloc(void *pClient) {
	int i;
	// Stop looking for clients at 32.
	for (i = 0; i < MAX_CLIENT; i++) {
		// If current entry is blank.
		if (bss.pClient_fs[i] == 0) {
			log_printf("Found uninitialized client at number %i.", i);
			// Set the BSS client entry to our own client
			bss.pClient_fs[i] = pClient;
			return i;
		}
	}
	log_printf("client_num_alloc failed to find a client");
	return -1;
}
// Clears a client slot.
// TODO: this is msspelt lol
// see id fix it but i dont wanna break smth
static void clietn_num_free(int client) {
	// CLear the entry.
	bss.pClient_fs[client] = 0;
}
// Gets the slot of a client.
static int client_num(void *pClient) {
	int i;

	// For every slot.
	for (i = 0; i < MAX_CLIENT; i++)
		// Check if the entry is the client we're looking for.
		if (bss.pClient_fs[i] == pClient)
			return i;
	return -1;
}

/* *****************************************************************************
 * This is powerful macro is used to modify system functions.
 * When expanded, it creates a function DECLaration that will allow us to do so.
 * Here we'll be making our custom functions, and we'll hook them later.
 * You can branch to the original function when your custom one has finished,
 * since the macro doesn't do this.
 * The syntax for this goes as follows:
 * res - The type of what the function returns (The original and modified
 * functions must have the same return type).
 * name - The name of the function to hook.
 * ... - Parameters to the function (Again, has to be same for both functions).
 * This info can be obtained from WiiUBru, or REing.
 * ****************************************************************************/
#define DECL(res, name, ...) \
        res (* real_ ## name)(__VA_ARGS__) __attribute__((section(".data"))); \
        res my_ ## name(__VA_ARGS__)

/* *****************************************************************************
 * Here is an example for a FSReadFile hook:
 * DECL(int, FSReadFile, void *pClient, void *pCmd, void *buffer, int size,
 * int count, int fd, int flag, int error) {
 * First, there's an integer return type, which indicates the success of the
 * operation a lot of the time. 0 means successfull, otherwise means there was
 * an error.
 * Then, there's the name of the function, FSReadFile.
 * Finally, there's quite a few parameters.
 * Now, there's any code that you want. You can use any of the parameters
 * freely like so:
 * cafiine_fread(bss.socket_fsa[client], &ret, buffer, size, count, fd);
 *
 * The declaration macro here would expand to:
 * int (* real_FSReadFile)(void *pClient, void *pCmd, void *buffer, int size,
 * int count, int fd, int flag, int error) __attribute__((section(".data")));
 * This creates a function pointer to the original system function variable,
 * and places it in the data sectiom of the binary.
 *
 * Onto the next line:
 * int my_FSReadFile(void *pClient, void *pCmd, void *buffer, int size,
 * int count, int fd, int flag, int error) {
 * This starts a function declaration for our own hook, hence the my_ prepended
 * to the function name.
 * ****************************************************************************/

/* *****************************************************************************
 * Creates function pointer array
 * ****************************************************************************/
 // Like FSInit, but only used by system RPLs.
 DECL(int, FSAInit, void) {
	 log_init("192.168.1.195");
   log_printf("FSAInit hook.");
	 /* This BSS section manipulation seems to just be an instance of Cafiine's
	  * code being outdated. Trying to relocate it in the HBL environment freezes,
	  * and commenting it out seems to run fine.
		*/

   // Check if bss_ptr points to a certain location (?)
   if ((int)bss_ptr == 0x0a000000) {
	 	//log_printf(".");
		// Allocate 40 bytes for a new BSS section, and point 0x100000e4 towards it.
    bss_ptr = memalign(0x40, sizeof(struct bss_t));
    // Initialize the new section to 0s.
    memset(bss_ptr, 0, sizeof(struct bss_t));
 	}
	log_deinit();
  // Normal execution.
 	return real_FSAInit();
 }

 DECL(int, FSAShutdown, void) {
 	return real_FSAShutdown();
 }

 DECL(int, FSAAddClient, void *r3) {
 	int res = real_FSAAddClient(r3);

 	if ((int)bss_ptr != 0x0a000000 && res < MAX_CLIENT && res >= 0) {
 		cafiine_connect(&bss.socket_fsa[res]);
 	}

 	return res;
 }
 DECL(int, FSADelClient, int client) {
 	if ((int)bss_ptr != 0x0a000000 && client < MAX_CLIENT && client >= 0) {
 		cafiine_disconnect(bss.socket_fsa[client]);
 	}

 	return real_FSADelClient(client);
 }
 DECL(int, FSAOpenFile, int client, const char *path, const char *mode, int *handle) {
 	if ((int)bss_ptr != 0x0a000000 && client < MAX_CLIENT && client >= 0) {
 		int ret;
 		if (cafiine_fopen(bss.socket_fsa[client], &ret, path, mode, handle) == 0)
 			return ret;
 	}

 	return real_FSAOpenFile(client, path, mode, handle);
 }

DECL(int, FSInit, void) {
	log_init("192.168.1.195");
	log_printf("FSInit hook.");

	// Check if bss_ptr points to a certain location (?)
	if ((int)bss_ptr == 0x0a000000) {
	 //log_printf("BSS PTR is pointing to 0x0A000000, realigning. Value: %0X", (int)bss_ptr);
	 //log_printf("%i", sizeof(struct bss_t));
	 //log_printf("zerp");
	 // Allocate 40 bytes for a new BSS section, and point 0x100000e4 towards it.
	 bss_ptr = memalign(0x40, sizeof(struct bss_t));
	 // Initialize the new section to 0s.
	 memset(bss_ptr, 0, sizeof(struct bss_t));
	 //log_printf("Writing new section adddress %0X to BSS Pointer at address %0X", newPtr, bss_ptr);
	 //bss_ptr = newPtr;
	 //log_printf("done");
 }
 // I think the reason this is done is that if the BSS section is at 0x0a000000, then
 // we won't have the permissions
	log_deinit();
	//log_printf("Continuing to normal execution.");
	return real_FSInit();
}
DECL(int, FSShutdown, void) {
	return real_FSShutdown();
}
DECL(int, FSAddClientEx, void *r3, void *r4, void *r5) {
	// r3 = client pointer
	// In the context, r3 is a new malloc'd client pointer
	log_init("192.168.1.195");
	log_printf("FSAddClientEx hook.");

	// Normal Execution.
	int res = real_FSAddClientEx(r3, r4, r5);

	// Find an empty client BSS entry to put our new one in.
	int client = client_num_alloc(r3);
	log_printf("Allocated new client number at slot %i.", client);
	// If the client is in a valid position.
	if (client < MAX_CLIENT && client >= 0) {
		// Connect to the Cafiine Server, and put the socket used in its respective
		// BSS entry for that client slot.
		cafiine_connect(&bss.socket_fs[client]);
		log_init("192.168.1.195");
		log_printf("Socket at client number %i is  %i", client, bss.socket_fs[client]);
	}

	log_deinit();

	return res;
}
DECL(int, FSDelClient, void *pClient) {
	// Make sure the BSS section isn't in the default place.
	if ((int)bss_ptr != 0x0a000000) {
		// Find the slot number for our client.
		int client = client_num(pClient);
		// If the client is in a valid position.
		if (client < MAX_CLIENT && client >= 0) {
			// Disconnect from the server.
			cafiine_disconnect(bss.socket_fs[client]);
			// Free the client slot.
			clietn_num_free(client);
		}
	}

	return real_FSDelClient(pClient);
}

DECL(int, FSReadFile, void *pClient, void *pCmd, void *buffer, int size, int count, int fd, int flag, int error) {
	log_init("192.168.1.195");
	log_printf("FSReadFile, size:  %i.", size);
	log_deinit();
	if ((int)bss_ptr != 0x0a000000 && ((fd & MASK_FD) == MASK_FD)) {
		int client = client_num(pClient);
		if (client < MAX_CLIENT && client >= 0) {
			int ret;
			if (cafiine_fread(bss.socket_fsa[client], &ret, buffer, size, count, fd) == 0) {
				return ret;
			}
		}
	}

	return real_FSReadFile(pClient, pCmd, buffer, size, count, fd, flag, error);
}
DECL(int, FSReadFileWithPos, void *pClient, void *pCmd, void *buffer, int size, int count, int pos, int fd, int flag, int error) {
	if ((int)bss_ptr != 0x0a000000 && ((fd & MASK_FD) == MASK_FD)) {
		int client = client_num(pClient);
		if (client < MAX_CLIENT && client >= 0) {
			int ret;
			if (cafiine_fsetpos(bss.socket_fsa[client], &ret, fd, pos) == 0) {
				if (cafiine_fread(bss.socket_fsa[client], &ret, buffer, size, count, fd) == 0) {
					return ret;
				}
			}
		}
	}

	return real_FSReadFileWithPos(pClient, pCmd, buffer, size, count, pos, fd, flag, error);
}
DECL(int, FSCloseFile, void *pClient, void *pCmd, int fd, int error) {
	if ((int)bss_ptr != 0x0a000000 && ((fd & MASK_FD) == MASK_FD)) {
		int client = client_num(pClient);
		if (client < MAX_CLIENT && client >= 0) {
			int ret;
			if (cafiine_fclose(bss.socket_fsa[client], &ret, fd) == 0) {
				return ret;
			}
		}
	}

	return real_FSCloseFile(pClient, pCmd, fd, error);
}
DECL(int, FSSetPosFile, void *pClient, void *pCmd, int fd, int pos, int error) {
	if ((int)bss_ptr != 0x0a000000 && ((fd & MASK_FD) == MASK_FD)) {
		int client = client_num(pClient);
		if (client < MAX_CLIENT && client >= 0) {
			int ret;
			if (cafiine_fsetpos(bss.socket_fsa[client], &ret, fd, pos) == 0) {
				return ret;
			}
		}
	}

	return real_FSSetPosFile(pClient, pCmd, fd, pos, error);
}

/*
DECL(int, FSOpenFile, void *pClient, void *pCmd, const char *path, const char *mode, int *handle, int error) {
	log_init("192.168.1.195");
	log_printf("FSOpenFile hook.");
	// Find the slot number for our client.
	int client = client_num(pClient);
	log_printf("Using client at slot %i", client);
	// If the client is in a valid position.
	if (client < MAX_CLIENT && client >= 0) {
		int ret;
		// Send the fopen to the server at the stored socket in the BSS.
		if (cafiine_fopen(bss.socket_fsa[client], &ret, path, mode, handle) == 0) {
			return ret;
		}
	}
	log_deinit();

	return real_FSOpenFile(pClient, pCmd, path, mode, handle, error);
}
*/
#define DUMP_BLOCK_SIZE (0x200 * 100)
#define DUMP_BLOCK_SIZE_SLOW (0x20 * 100)
DECL(int, FSOpenFile, void *pClient, void *pCmd, const char *path,
	const char *mode, int *handle, int error)
	{
		log_init("192.168.1.195");
		log_printf("FSOpenFile hook.");
    int my_ret = -1;
    error = 0xffffffff;
    if ((int)bss_ptr != 0x0a000000)
		{
			// Get the socket for the specified client.
      int client = client_num(pClient);
			log_printf("Socket at client number %i is  %i", client, bss.socket_fs[client]);
			// If it's valid.
      if (client < MAX_CLIENT && client >= 0)
			{
        int ret;
				// Send the open request to the server.
        my_ret = cafiine_fopen(bss.socket_fsa[client], &ret, path, mode, handle);
				// 0 is returned when we recieved a new file handle to use.
        if (my_ret == 0)
				{
          // File exists in Cafiine server, a new handle has been created.
          return ret;
        }
				// Everything else.
        else if (my_ret >= 1)
				{
          // File has been requested from Cafiine server.
          ret = real_FSOpenFile(pClient, pCmd, path, mode, handle, error);
					// All error codes are negative.
          if (ret >= 0)
					{
						// If Cafiine returned 1, use normal request.
						// Else, use the slow dumping speed.
            int size = (my_ret == 1 ? DUMP_BLOCK_SIZE : DUMP_BLOCK_SIZE_SLOW);
            cafiine_send_handle(bss.socket_fsa[client], client, path, *handle);
            void* buffer = memalign(sizeof(char) * size, 0x40);
            int ret2;
            while ((ret2 = real_FSReadFile(pClient, pCmd, buffer, 1, size, *handle, 0, error)) > 0)
                cafiine_send_file(bss.socket_fsa[client], buffer, ret2, *handle);
            cafiine_fclose(bss.socket_fsa[client], &ret2, *handle);
            real_FSSetPosFile(pClient, pCmd, *handle, 0, error);
          }
          return ret;
        }
      }
    }
		log_deinit();

    return real_FSOpenFile(pClient, pCmd, path, mode, handle, error);
}

DECL(int, FSGetPosFile, void *pClient, void *pCmd, int fd, int *pos, int error) {
	if ((int)bss_ptr != 0x0a000000 && ((fd & MASK_FD) == MASK_FD)) {
		int client = client_num(pClient);
		if (client < MAX_CLIENT && client >= 0) {
			int ret;
			if (cafiine_fgetpos(bss.socket_fsa[client], &ret, fd, pos) == 0) {
				return ret;
			}
		}
	}

	return real_FSGetPosFile(pClient, pCmd, fd, pos, error);
}
DECL(int, FSGetStatFile, void *pClient, void *pCmd, int fd, void *buffer, int error) {
	if ((int)bss_ptr != 0x0a000000 && ((fd & MASK_FD) == MASK_FD)) {
		int client = client_num(pClient);
		if (client < MAX_CLIENT && client >= 0) {
			int ret;
			if (cafiine_fstat(bss.socket_fsa[client], &ret, fd, buffer) == 0) {
				return ret;
			}
		}
	}

	return real_FSGetStatFile(pClient, pCmd, fd, buffer, error);
}
DECL(int, FSIsEof, void *pClient, void *pCmd, int fd, int error) {
	if ((int)bss_ptr != 0x0a000000 && ((fd & MASK_FD) == MASK_FD)) {
		int client = client_num(pClient);
		if (client < MAX_CLIENT && client >= 0) {
			int ret;
			if (cafiine_feof(bss.socket_fsa[client], &ret, fd) == 0) {
				return ret;
			}
		}
	}

	return real_FSIsEof(pClient, pCmd, fd, error);
}

/* *****************************************************************************
 * Now that we have our function declarations, we will peice them together in
 * a struct to make the actual hooking later easy.
 * This macro takes in a function name, and outputs it in 3 different ways:
 * - A callable function with my_ prepended to represent our hook
 * - A callable function with &real prepended to represent the original
 * - The dynamic library the function is located in.
 * Choices are as stated in common.h, LIB_CORE_INIT (coreinit.rpl), LIB_NSYSNET
 * (nsysnet.rpl), and LIB_GX2 (gx2.rpl)
 * - The name of the function
 * ****************************************************************************/
#define MAKE_MAGIC(x, lib) { (unsigned int) my_ ## x, (unsigned int) &real_ ## x, lib, # x }

// This is a table containing info about our hooks that we'll be operating on
static const struct hooks_magic_t {
  const unsigned int replaceAddr;
  const unsigned int replaceCall;
  const unsigned int library;
  const char functionName[30];
} method_hooks[] = {
  MAKE_MAGIC(FSAInit,       LIB_CORE_INIT),
  MAKE_MAGIC(FSAShutdown,   LIB_CORE_INIT),
  MAKE_MAGIC(FSAAddClient,  LIB_CORE_INIT),
  MAKE_MAGIC(FSADelClient,  LIB_CORE_INIT),
  MAKE_MAGIC(FSAOpenFile,   LIB_CORE_INIT),

  MAKE_MAGIC(FSInit,        LIB_CORE_INIT),
  MAKE_MAGIC(FSShutdown,    LIB_CORE_INIT),
  MAKE_MAGIC(FSAddClientEx, LIB_CORE_INIT),
  MAKE_MAGIC(FSDelClient,   LIB_CORE_INIT),
  MAKE_MAGIC(FSOpenFile,    LIB_CORE_INIT),
  MAKE_MAGIC(FSCloseFile,   LIB_CORE_INIT),
  /* *****************************************************************************
   * This expands to:
   * Our local defined replacement function.
   * (unsigned int) my_FSReadFile,
   * The address of the real function.
   * (unsigned int) &real_FSReadFile
   * The library
  * ****************************************************************************/
  MAKE_MAGIC(FSReadFile,    LIB_CORE_INIT),
  MAKE_MAGIC(FSReadFileWithPos, LIB_CORE_INIT),
  MAKE_MAGIC(FSGetPosFile,  LIB_CORE_INIT),
  MAKE_MAGIC(FSSetPosFile,  LIB_CORE_INIT),
  MAKE_MAGIC(FSGetStatFile, LIB_CORE_INIT),
  MAKE_MAGIC(FSIsEof,       LIB_CORE_INIT),
};

//! buffer to store our 2 instructions needed for our replacements
//! the code will be placed in the address of that buffer - CODE_RW_BASE_OFFSET
//! avoid this buffer to be placed in BSS and reset on start up
volatile unsigned int fs_method_calls[sizeof(method_hooks) / sizeof(struct hooks_magic_t) * 2] __attribute__((section(".data")));

void PatchMethodHooks(void)
{
	log_print("Gathering hook info from memory...\n");
  // At address 0x00801600, we have a table of data used to keep track of all of
	// the hooks
  restore_instructions_t * restore = (restore_instructions_t *)(RESTORE_INSTR_ADDR);
  // Check if we already hooked the method and set the magic to 0xC001C0DE
  if(restore->magic == RESTORE_INSTR_MAGIC)
	{
		log_print("Cafiine is already installed.\n");
    // Nothing needs to be done.
    return;
	}
	log_print("Beginning Cafiine Function Hooking!\n");

  // Now that we're going to hook the methods, we can mark the magic as done
  restore->magic = RESTORE_INSTR_MAGIC;
  // Reset the number of instructions hooked
  restore->instr_count = 0;

  // (D)BAT = (Data) Block Address Translation
  // Converts virtual address to physical address
  bat_table_t table;
  // Fix up the table to point to new address
  KernelSetDBATs(&table);

  // Get a pointer to the first instruction
	// size : 34
  volatile unsigned int *space = &fs_method_calls[0];

  // Get the number of hooks
  int method_hooks_count = sizeof(method_hooks) / sizeof(struct hooks_magic_t);

  // For every hook
  for(int i = 0; i < method_hooks_count; i++)
  {
		log_printf("Hooking function number %i: %s...", i, method_hooks[i].functionName);
    // Get our own function hook (my_)
    unsigned int repl_addr = (unsigned int)method_hooks[i].replaceAddr;
    // Get the original function pointer (&real)
    unsigned int call_addr = (unsigned int)method_hooks[i].replaceCall;
    // We don't know the address of the funciton
    unsigned int real_addr = 0;

    // If the currrent hook is for OSDynLoad_Acquire
    if(strcmp(method_hooks[i].functionName, "OSDynLoad_Acquire") == 0)
    {
      // Just copy over the address?
      memcpy(&real_addr, &OSDynLoad_Acquire, 4);
    }
    // For any other function hook
    else
    {
    	// Get the address of the function in question and put it in real_addr
      // TODO: This only works for CoreInit.rpl stuff, should be expanded for nsysnet and gx2
			int error = OSDynLoad_FindExport(coreinit_handle, 0, method_hooks[i].functionName, &real_addr);
      if(error != 0)
			{
				log_printf("Function export failed with error %i, skipping.", error);
				continue;
			}
    }

    // Go to the last instruction, and set it's address to the one we just
		// obtained with OSDynLoad_FindExport
    restore->data[restore->instr_count].addr = real_addr;
		log_printf("Hook instruction address: %X actual, %X original\n", LIB_CODE_RW_BASE_OFFSET + real_addr, real_addr);
		// Setting the instr feild of our table to the first original instruction
		// at the address
    restore->data[restore->instr_count].instr = *(volatile unsigned int *)(LIB_CODE_RW_BASE_OFFSET + real_addr);
    // Increment the count
    restore->instr_count++;

    // Assign an address to our original callable function pointer
		// ???
    *(volatile unsigned int *)(call_addr) = (unsigned int)(space) - CODE_RW_BASE_OFFSET;
    DCFlushRange((void*)(call_addr), 4);

    // Fill the first buffer index with the current address's first original
		// instruction, saving it for later
    *space = *(volatile unsigned int*)(LIB_CODE_RW_BASE_OFFSET + real_addr);
		// Move onto the next instruction to be saved
    space++;

    // jump to real function skipping the first/replaced instruction
		// -------
		// Fill the second buffer index with a PPC jump instruction (?) to the
		// second instructuction of the originl function
		// real_addr + 4 - I believe that instructions are 4 bytes long, so this
		// skips the instruction we just wrote to the first index
    *space = 0x48000002 | ((real_addr + 4) & 0x03fffffc);
    space++;
    DCFlushRange((void*)(space - 2), 8);
    ICInvalidateRange((unsigned char*)(space - 2) - CODE_RW_BASE_OFFSET, 8);

    unsigned int replace_instr = 0x48000002 | (repl_addr & 0x03fffffc);
    *(volatile unsigned int *)(LIB_CODE_RW_BASE_OFFSET + real_addr) = replace_instr;
    DCFlushRange((void*)(LIB_CODE_RW_BASE_OFFSET + real_addr), 4);
    ICInvalidateRange((void*)(real_addr), 4);
  }

  KernelRestoreDBATs(&table);
}

/* ****************************************************************** */
/*                  RESTORE ORIGINAL INSTRUCTIONS                     */
/* ****************************************************************** */
void RestoreInstructions(void)
{
    bat_table_t table;
    KernelSetDBATs(&table);

    restore_instructions_t * restore = (restore_instructions_t *)(RESTORE_INSTR_ADDR);
    if(restore->magic == RESTORE_INSTR_MAGIC)
    {
        for(unsigned int i = 0; i < restore->instr_count; i++)
        {
            *(volatile unsigned int *)(LIB_CODE_RW_BASE_OFFSET + restore->data[i].addr) = restore->data[i].instr;
            DCFlushRange((void*)(LIB_CODE_RW_BASE_OFFSET + restore->data[i].addr), 4);
            ICInvalidateRange((void*)restore->data[i].addr, 4);
        }

    }
    restore->magic = 0;
    restore->instr_count = 0;

    KernelRestoreDBATs(&table);
    KernelRestoreInstructions();
}
