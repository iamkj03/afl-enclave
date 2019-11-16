#include <cstdio>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "Enclave_t.h"
#include <stdlib.h>

char message[200];

extern "C" char* getenv (const char *name){
	char* ret;
	if(ocall_getenv(&ret, name) != SGX_SUCCESS) return 0;
	snprintf(message, 200, "*ret: %s\n", ret);
	print_message(message);
	return ret;
}

//int shmget(key_t key, int size, int shmflg);
extern "C" int shmget(key_t key, int size, int shmflg){

	int ret;
	
    if (ocall_shmget(&ret, key, size, shmflg) != SGX_SUCCESS) return -1;
    
	return ret;
}

extern "C" int* shmat (int shmid, const char *shmaddr, int shmflg){

	int *ret;
    if (ocall_shmat(&ret, shmid, shmaddr, shmflg) != SGX_SUCCESS) return 0;
    
	return ret;
}


int stdin = 0, stdout = 1, stderr = 2;

extern "C" int read(int file, void *buf, unsigned int size) {
    int ret;
    if (ocall_read(&ret, file, buf, size) != SGX_SUCCESS) return -1;
    return ret;
}

extern "C" int write(int file, void *buf, unsigned int size) {
    int ret;
    if (ocall_write(&ret, file, buf, size) != SGX_SUCCESS) return -1;
    return ret;
}

extern "C" void close(int file) {
    ocall_close(file);
}

extern "C" int fork(void){
    int ret;
    if (ocall_fork(&ret) != SGX_SUCCESS) return -1;
    return ret;
    /*return 0;*/
}

extern "C" int waitpid(int pid, int *state, int options){
    int ret;
    if (ocall_waitpid(&ret, pid, state, options) != SGX_SUCCESS) return -1;
    return ret;
	/*return 0;*/
}

extern "C" void _exit (int state){
    ocall__exit(state);
}


#define	 IPC_CREAT 	01000

void execute_secure_operation(uint8_t* sealed_data, uint32_t sealed_data_size, int password) {
    int unsealed_value;
    char tries[400]; //for later use(contains password trials until correct.
    int shmid;    
    int* shared_memory = 0;    // 공유메모리 공간을 만든다.// 크기는 4byte로 한다. 
    char data[128];
    const void *buf = "An error occurred in the read.\n";
    //const char *p = "PATH";
 
    
    snprintf(tries, 400, "After initialization of unsealed_value, tries, and before initialization before sgx_status status = unseal((sgx_sealded_data_t*) sealed_data, sealed_data_size, (uint8_t*) &unsealed_value, sizeof(unsealed_value)", unsealed_value);
    print_message(tries);

    sgx_status_t status = unseal((sgx_sealed_data_t*) sealed_data, sealed_data_size,
            (uint8_t*) &unsealed_value, sizeof(unsealed_value));

    snprintf(tries, 200, "After sgx_status_t status = unseal((sgx_sealed_data_t*) sealed_data, sealed_data_size, (uint8_t*) &unsealed_value, sizeof(unsealed_value));", unsealed_value);
    print_message(tries);

    if(password == 1234) {
	snprintf(message, 200, "Successful login", unsealed_value);
	print_message(message);
	unsealed_value = password;
        seal((uint8_t*) &unsealed_value, sizeof(unsealed_value),
            (sgx_sealed_data_t*) sealed_data, sealed_data_size);}
    else{
	snprintf(message, 200, "You have entered wrong password, you have entered ****", password);
	print_message(message);
	return;}    

    /* This data should never leave enclave, here it's just for the demo. */
    snprintf(message, 200, "This is just to check, never should happen. Printing from enclave, just to see what's inside: %d", unsealed_value);
    print_message(message);

    //TEST
    snprintf(message, 200, "====================FROM HERE, this is test for function ===============", unsealed_value);
    print_message(message);

	shmid = shmget(7530, 1028, IPC_CREAT|0666) ;

  
    shared_memory = shmat(shmid, (char *)0, 0);  
    snprintf(message, 200, "shmat is %x", shared_memory);
    print_message(message);  

    /*if(read(0, data, 128)>0){
       snprintf(message, 200, "read(0, data, 128) is %d", read(0,data,128));
       print_message(message);
       write(2, &buf, 31);
       snprintf(message, 200, "write(2, &buf, 31) is %d", write(2, &buf, 31));
       print_message(message);

       snprintf(message, 200, "_exit(0); executed", password);
       print_message(message);       
       _exit(0);

    }*/

    
    fork();
    snprintf(message, 200, "Fork testing worked if printed 2 times", password);
    print_message(message);
    
    snprintf(message, 200, "PATH: %d\n", getenv("PATH"));
    print_message(message);
}

void initialize_enclave_data(uint8_t* sealed_data, uint32_t sealed_data_size, int initial_value) {
    seal((uint8_t*) &initial_value, sizeof(initial_value),
            (sgx_sealed_data_t*) sealed_data, sealed_data_size);

    /* This data should never leave enclave, here it's just for the demo. */
    snprintf(message, 200, "Initializing enclave data with value: %d", initial_value);
    print_message(message);
}
