#include <stdio.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
const char *data_filename = "sealed.data";

// OCALL implementations
void print_message(const char* str) {
    std::cout << str << std::endl;
}

int ocall_read(int file, void *buf, unsigned int size) {
    printf("ocall_read(file: %d, void buf: buf, unsigned int: %d): %d\n",file, size, read(file, buf, size));
    return read(file, buf, size);
}

int ocall_write(int file, void *buf, unsigned int size) {
    printf("ocall_write(file: %d, void buf: buf, unsigned int: %d): %d\n",file, size, write(file, buf, size));
    return write(file, buf, size);
}

void ocall_close(int file) {
    printf("ocall_close(file: %d)", file);
    close(file);
}

void ocall__exit(int state) {
     printf("ocall__exit(state: %d)", state);
     _exit(state);
}
    
int ocall_waitpid(int pid, int *state, int options){
     printf("ocall_waitpid(pid: %d, state: %d, options: %d): %d\n", pid, &state, options);
     return waitpid(pid, state, options);
}

int ocall_fork(void){
     printf("fork succeeded\n");
     fork();
}

int* ocall_shmat(int shmid, const char *shmaddr, int shmflg){
     printf("what is inside shmat(shmid: %d, shmaddr: , shmflg: %d)\n", shmid, shmflg );
     return (int*)shmat(shmid, shmaddr, shmflg); //print something here
}

char* ocall_getenv (const char *name){
     printf("ocall_getenv(%s) called\n", name);
     printf("Path is %s\n", getenv(name));
     return getenv(name);
}

//int shmget(key_t key, int size, int shmflg);
int ocall_shmget(int key, int size, int shmflg){
     int ret = 0;
	 printf("ocall_shmget(key: %d, size: , shmflg: %d)\n", key, size, shmflg);
	 
	 ret = shmget((key_t)key, size, shmflg);
	 
     return ret; 
}

int read_password() {
  int password;
  std::cout << "Password : ";
  std::cin >> password;
  return std::cin.fail() ? -1 : password;
}

int load_data(uint8_t *sealed_data, size_t sealed_size) {
  FILE *fp = fopen(data_filename, "rb");
  if (fp == NULL) {
      printf("\"%s\"No Sealed.data. Creating new one...\n", data_filename);
      initialize_enclave_data(global_eid, sealed_data, sealed_size, 0);
  } else {
      size_t read_num = fread(sealed_data, 1, sealed_size, fp);
      if (read_num != sealed_size) {
          printf("Warning: Failed to read sealed data from \"%s\" (%zu bytes read).\n", data_filename, read_num);
          return -1;
      }
      fclose(fp);
  }
}

int save_data(uint8_t *sealed_data, size_t sealed_size) {
  FILE *fp = fopen("sealed.data", "wb");
  if (fp) {
      size_t write_num = fwrite(sealed_data, 1, sealed_size, fp);
      if (write_num != sealed_size) {
          printf("Warning: Failed to save sealed data to \"%s\" (%zu bytes written).\n", data_filename, write_num);
          return -1;
        }
      fclose(fp);
  }
}

int main(int argc, char const *argv[]) {
    int password;
    char id[16];

    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(int);
    uint8_t* sealed_data = (uint8_t*) malloc(sealed_size);

    load_data(sealed_data, sealed_size);
    std::cout << "Login ID : ";
    std::cin >> id;

    if((password = read_password()) < 0) {
	std::cout << "Provide a correct integer password!" << std::endl;
	return -1;
    }
    

    if (load_data(sealed_data, sealed_size) < 0) {
      return -1;
    };

    std::cout << "load_data(" << sealed_size << ", " << &sealed_data << ") : " << load_data(sealed_data, sealed_size) << std::endl;
    
    if(strcmp(id,"root") == 0){
        std::cout << "If id is root, Before EXECUTING ECALL (execute_secure_operation(global_eid, sealed_data, sealed_size, password)" << std::endl;
	execute_secure_operation(global_eid, sealed_data, sealed_size, password);
        std::cout << "After EXECUTING ECALL (executing_secure_operation(global_eid, sealed_data, sealded_size, password)" << std::endl;}
    else{
	std::cout << "Incorrect login" << std::endl;}

    if (save_data(sealed_data, sealed_size) < 0) {
      return -1;
    }

    return 0;
}
