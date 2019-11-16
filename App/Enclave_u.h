#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PRINT_MESSAGE_DEFINED__
#define PRINT_MESSAGE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, print_message, (const char* str));
#endif
#ifndef OCALL_READ_DEFINED__
#define OCALL_READ_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read, (int file, void* buf, unsigned int size));
#endif
#ifndef OCALL_WRITE_DEFINED__
#define OCALL_WRITE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write, (int file, void* buf, unsigned int size));
#endif
#ifndef OCALL_CLOSE_DEFINED__
#define OCALL_CLOSE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close, (int file));
#endif
#ifndef OCALL__EXIT_DEFINED__
#define OCALL__EXIT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall__exit, (int state));
#endif
#ifndef OCALL_WAITPID_DEFINED__
#define OCALL_WAITPID_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_waitpid, (int pid, int* state, int options));
#endif
#ifndef OCALL_FORK_DEFINED__
#define OCALL_FORK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fork, (void));
#endif
#ifndef OCALL_SHMGET_DEFINED__
#define OCALL_SHMGET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_shmget, (key_t key, int size, int shmflg));
#endif
#ifndef OCALL_SHMAT_DEFINED__
#define OCALL_SHMAT_DEFINED__
int* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_shmat, (int shmid, const char* shmaddr, int shmflg));
#endif
#ifndef OCALL_GETENV_DEFINED__
#define OCALL_GETENV_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getenv, (const char* name));
#endif

sgx_status_t execute_secure_operation(sgx_enclave_id_t eid, uint8_t* sealed_data, uint32_t sealed_data_size, int password);
sgx_status_t initialize_enclave_data(sgx_enclave_id_t eid, uint8_t* sealed_data, uint32_t sealed_data_size, int initial_value);
sgx_status_t seal(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t unseal(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
