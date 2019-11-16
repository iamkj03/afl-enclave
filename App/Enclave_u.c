#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_execute_secure_operation_t {
	uint8_t* ms_sealed_data;
	uint32_t ms_sealed_data_size;
	int ms_password;
} ms_execute_secure_operation_t;

typedef struct ms_initialize_enclave_data_t {
	uint8_t* ms_sealed_data;
	uint32_t ms_sealed_data_size;
	int ms_initial_value;
} ms_initialize_enclave_data_t;

typedef struct ms_seal_t {
	sgx_status_t ms_retval;
	uint8_t* ms_plaintext;
	size_t ms_plaintext_len;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_seal_t;

typedef struct ms_unseal_t {
	sgx_status_t ms_retval;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
	uint8_t* ms_plaintext;
	uint32_t ms_plaintext_len;
} ms_unseal_t;

typedef struct ms_print_message_t {
	const char* ms_str;
} ms_print_message_t;

typedef struct ms_ocall_read_t {
	int ms_retval;
	int ms_file;
	void* ms_buf;
	unsigned int ms_size;
} ms_ocall_read_t;

typedef struct ms_ocall_write_t {
	int ms_retval;
	int ms_file;
	void* ms_buf;
	unsigned int ms_size;
} ms_ocall_write_t;

typedef struct ms_ocall_close_t {
	int ms_file;
} ms_ocall_close_t;

typedef struct ms_ocall__exit_t {
	int ms_state;
} ms_ocall__exit_t;

typedef struct ms_ocall_waitpid_t {
	int ms_retval;
	int ms_pid;
	int* ms_state;
	int ms_options;
} ms_ocall_waitpid_t;

typedef struct ms_ocall_fork_t {
	int ms_retval;
} ms_ocall_fork_t;

typedef struct ms_ocall_shmget_t {
	int ms_retval;
	int ms_key;
	int ms_size;
	int ms_shmflg;
} ms_ocall_shmget_t;

typedef struct ms_ocall_shmat_t {
	int* ms_retval;
	int ms_shmid;
	const char* ms_shmaddr;
	int ms_shmflg;
} ms_ocall_shmat_t;

typedef struct ms_ocall_getenv_t {
	char* ms_retval;
	const char* ms_name;
} ms_ocall_getenv_t;

static sgx_status_t SGX_CDECL Enclave_print_message(void* pms)
{
	ms_print_message_t* ms = SGX_CAST(ms_print_message_t*, pms);
	print_message(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read(void* pms)
{
	ms_ocall_read_t* ms = SGX_CAST(ms_ocall_read_t*, pms);
	ms->ms_retval = ocall_read(ms->ms_file, ms->ms_buf, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write(void* pms)
{
	ms_ocall_write_t* ms = SGX_CAST(ms_ocall_write_t*, pms);
	ms->ms_retval = ocall_write(ms->ms_file, ms->ms_buf, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_close(void* pms)
{
	ms_ocall_close_t* ms = SGX_CAST(ms_ocall_close_t*, pms);
	ocall_close(ms->ms_file);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall__exit(void* pms)
{
	ms_ocall__exit_t* ms = SGX_CAST(ms_ocall__exit_t*, pms);
	ocall__exit(ms->ms_state);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_waitpid(void* pms)
{
	ms_ocall_waitpid_t* ms = SGX_CAST(ms_ocall_waitpid_t*, pms);
	ms->ms_retval = ocall_waitpid(ms->ms_pid, ms->ms_state, ms->ms_options);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fork(void* pms)
{
	ms_ocall_fork_t* ms = SGX_CAST(ms_ocall_fork_t*, pms);
	ms->ms_retval = ocall_fork();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_shmget(void* pms)
{
	ms_ocall_shmget_t* ms = SGX_CAST(ms_ocall_shmget_t*, pms);
	ms->ms_retval = ocall_shmget(ms->ms_key, ms->ms_size, ms->ms_shmflg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_shmat(void* pms)
{
	ms_ocall_shmat_t* ms = SGX_CAST(ms_ocall_shmat_t*, pms);
	ms->ms_retval = ocall_shmat(ms->ms_shmid, ms->ms_shmaddr, ms->ms_shmflg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getenv(void* pms)
{
	ms_ocall_getenv_t* ms = SGX_CAST(ms_ocall_getenv_t*, pms);
	ms->ms_retval = ocall_getenv(ms->ms_name);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[10];
} ocall_table_Enclave = {
	10,
	{
		(void*)Enclave_print_message,
		(void*)Enclave_ocall_read,
		(void*)Enclave_ocall_write,
		(void*)Enclave_ocall_close,
		(void*)Enclave_ocall__exit,
		(void*)Enclave_ocall_waitpid,
		(void*)Enclave_ocall_fork,
		(void*)Enclave_ocall_shmget,
		(void*)Enclave_ocall_shmat,
		(void*)Enclave_ocall_getenv,
	}
};
sgx_status_t execute_secure_operation(sgx_enclave_id_t eid, uint8_t* sealed_data, uint32_t sealed_data_size, int password)
{
	sgx_status_t status;
	ms_execute_secure_operation_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_data_size = sealed_data_size;
	ms.ms_password = password;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t initialize_enclave_data(sgx_enclave_id_t eid, uint8_t* sealed_data, uint32_t sealed_data_size, int initial_value)
{
	sgx_status_t status;
	ms_initialize_enclave_data_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_data_size = sealed_data_size;
	ms.ms_initial_value = initial_value;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t seal(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status;
	ms_seal_t ms;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_len = plaintext_len;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t unseal(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len)
{
	sgx_status_t status;
	ms_unseal_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_len = plaintext_len;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

