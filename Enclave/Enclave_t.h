#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

typedef int key_t;

#ifdef __cplusplus
extern "C" {
#endif

void execute_secure_operation(uint8_t* sealed_data, uint32_t sealed_data_size, int password);
void initialize_enclave_data(uint8_t* sealed_data, uint32_t sealed_data_size, int initial_value);
sgx_status_t seal(uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t unseal(sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len);

sgx_status_t SGX_CDECL print_message(const char* str);
sgx_status_t SGX_CDECL ocall_read(int* retval, int file, void* buf, unsigned int size);
sgx_status_t SGX_CDECL ocall_write(int* retval, int file, void* buf, unsigned int size);
sgx_status_t SGX_CDECL ocall_close(int file);
sgx_status_t SGX_CDECL ocall__exit(int state);
sgx_status_t SGX_CDECL ocall_waitpid(int* retval, int pid, int* state, int options);
sgx_status_t SGX_CDECL ocall_fork(int* retval);
sgx_status_t SGX_CDECL ocall_shmget(int* retval, key_t key, int size, int shmflg);
sgx_status_t SGX_CDECL ocall_shmat(int** retval, int shmid, const char* shmaddr, int shmflg);
sgx_status_t SGX_CDECL ocall_getenv(char** retval, const char* name);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
