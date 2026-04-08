#pragma once
#ifdef __cplusplus
extern "C" {
#endif

char* zkap_generate_hash(const char* input_json);
char* zkap_generate_anchor(const char* input_json);
char* zkap_generate_aud_hash(const char* input_json);
char* zkap_generate_leaf_hash(const char* input_json);
char* zkap_prove(const char* input_json);
void  zkap_free_string(char* ptr);

#ifdef __cplusplus
}
#endif
