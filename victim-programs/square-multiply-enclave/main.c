#include <stdio.h>
#include <string.h>

#include "sgx_urts.h"
#include "enclave_u.h"


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;


uint32_t key = 0; // unknown

int main() {
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated = 0;

  // Create enclave
  if(sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL) != SGX_SUCCESS) {
      printf("Failed to start enclave!\n");
      return -1;
  }
  uint64_t plaintext = 3;
  uint64_t modulus = 0x80000000; // 31-bits
  
  printf("main @ %p\n", main);
  
  fread(&key, sizeof(key), 8, stdin); // concolic execution to find secret key
  printf("Key = %u\n", key);
  printf("Modulus = %lu\n", modulus);
  uint64_t result = 0;
  mod_exp(global_eid, &result, plaintext, key, modulus); // mod_exp = RSA with side-channel leakage
  printf("Ciphertext = %lu\n", result);
  return 0;
}


