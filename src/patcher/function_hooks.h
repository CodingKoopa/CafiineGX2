#ifndef _FUNCTION_HOOKS_H_
#define _FUNCTION_HOOKS_H_

#ifdef __cplusplus
extern "C" {
#endif

void PatchMethodHooks(void);
void RestoreInstructions(void);

void cafiine_connect(int *socket);
void cafiine_disconnect(int socket);
int cafiine_fopen(
	int socket, int *result, const char *path, const char *mode, int *handle);
void cafiine_send_handle(int sock, int client, const char *path, int handle);
void cafiine_send_file(int sock, char *file, int size, int fd);
int cafiine_fread(
	int socket, int *result, void *buffer, int size, int count, int fd);
int cafiine_fclose(int socket, int *result, int fd);
int cafiine_fsetpos(int socket, int *result, int fd, int set);
int cafiine_fgetpos(int socket, int *result, int fd, int *pos);
int cafiine_fstat(int sock, int *result, int fd, void *ptr);
int cafiine_feof(int sock, int *result, int fd);

#ifdef __cplusplus
}
#endif

#endif /* _FS_H */
