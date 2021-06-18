#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <naemon/naemon.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>

NEB_API_VERSION(CURRENT_NEB_API_VERSION);

enum {
	VAULT_FILE = 0,
	VAULT_PW
};

const char *module_opts[] = {
	[VAULT_FILE] = "vault",
	[VAULT_PW]   = "password"
};

const char *master_password_store_key = "master_password_store_key";
static void *neb_handle = NULL;
static char *vault_file = NULL;
static char *master_password = NULL;
struct kvvec *macro_store;

/* handle the macro replacement by looking up macro in the macro store */
static int handle_vault_macro(int cb, void *_ds) {
	nebstruct_vault_macro_data *ds = (nebstruct_vault_macro_data *)_ds;
	char *value = kvvec_fetch_str_str(macro_store, ds->macro_name);
	if(value != NULL) {
		nm_free(ds->value);
		ds->value = strdup(value);
		return OK;
	}
	return OK;
}

/* parse module load arguments */
int parse_args(char *arg) {
	char *arg_value;
	arg = strtok(arg, " \t");
	while(arg != NULL) {
		switch (getsubopt (&arg, (char * const* restrict)module_opts, &arg_value)) {
			case VAULT_FILE:
				vault_file = arg_value;
				break;
			case VAULT_PW:
				master_password = arg_value;
				break;
			default:
				nm_log(NSLOG_INFO_MESSAGE, "Error: unknown module argument: %s", arg_value);
				return ERROR;
		}
		arg = strtok(NULL, " \t");
	}

	if(vault_file == NULL) {
		nm_log(NSLOG_INFO_MESSAGE, "Error: 'vault' is a required argument");
		return ERROR;
	}
}

/* convert 32byte into hex string */
char *hexstr32(unsigned char *string) {
	static unsigned char hexit[65];
	for (int j = 0; j < 32; j++)
		sprintf((char *)hexit + j * 2, "%02x", string[j]);
	hexit[sizeof(hexit) - 1] = '\0';
	return hexit;
}

/* calculate sha256 sum with salt */
unsigned char *sha256_key(char *string, char *salt, int salt_len) {
	static unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, string, strlen(string));
	SHA256_Update(&sha256, salt, salt_len);
	SHA256_Final(hash, &sha256);
	return hash;
}

/* read raw encrypted vault file data */
int read_raw_vault(char **buffer, int *buffer_size, char **salt) {
	FILE *fp;

	fp = fopen(vault_file, "rb");
	if(!fp) {
		nm_log(NSLOG_INFO_MESSAGE, "Error: cannot read vault file %s: %d - %s", vault_file, errno, strerror(errno));
		return ERROR;
	}

	fseek(fp , 0L , SEEK_END);
	*buffer_size = ftell(fp) - 20; // 12 bytes vimcrypt header, 8 byte salt
	rewind(fp);

	*buffer = nm_malloc(*buffer_size);
	if(1 != fread(*buffer , 9, 1 , fp)) {
		nm_log(NSLOG_INFO_MESSAGE, "Error: cannot read vault file %s: %d - %s", vault_file, errno, strerror(errno));
		fclose(fp);
		free(*buffer);
		return ERROR;
	}
	if(strncmp("VimCrypt~", *buffer, 9) != 0) {
		nm_log(NSLOG_INFO_MESSAGE, "Error: file %s is not a vim crypted file.", vault_file);
		fclose(fp);
		free(*buffer);
		return ERROR;
	}

	if(1 != fread(*buffer , 3, 1 , fp)) {
		nm_log(NSLOG_INFO_MESSAGE, "Error: cannot read vault file %s: %d - %s", vault_file, errno, strerror(errno));
		fclose(fp);
		free(*buffer);
		return ERROR;
	}
	if(strncmp("03!", *buffer, 3) != 0) {
		nm_log(NSLOG_INFO_MESSAGE, "Error: %s uses unsupported crypt method, only blowfish2 is supported.", vault_file);
		fclose(fp);
		free(*buffer);
		return ERROR;
	}

	/* read 8 bytes of salt */
	*salt = nm_malloc(8);
	if(1 != fread(*salt , 8, 1 , fp)) {
		nm_log(NSLOG_INFO_MESSAGE, "Error: cannot read vault file %s: %d - %s", vault_file, errno, strerror(errno));
		fclose(fp);
		free(*buffer);
		free(*salt);
		return ERROR;
	}

	/* copy the remaining file into the buffer */
	if(1 != fread(*buffer , *buffer_size, 1 , fp)) {
		nm_log(NSLOG_INFO_MESSAGE, "Error: cannot read vault file %s: %d - %s", vault_file, errno, strerror(errno));
		fclose(fp);
		free(*buffer);
		free(*salt);
		return ERROR;
	}
	fclose(fp);
	return(OK);
}

/* returns blowfish 2 handle */
BF_KEY *bfopen(char*salt, int salt_len) {
	static BF_KEY bfkey;
	int keylen = SHA256_DIGEST_LENGTH;
	unsigned char *key;

	key = hexstr32(sha256_key(master_password, salt, salt_len));
	for(int i = 0; i < 999; i++)
		key = hexstr32(sha256_key(key, salt, salt_len));
	key = sha256_key(key, salt, salt_len);
	key[keylen] = '\0';

	BF_set_key(&bfkey, keylen, key);
	return(&bfkey);
}

void xor_bytes(char *dst, char *b1, char *b2, int size) {
	for(int i = 0; i < size; i++)
		dst[i] = b1[i] ^ b2[i];
}

/* decrypt vault content */
void decrypt_vault(char **decrypted, char *encrypted, int enc_size, char *salt) {
	BF_KEY *bfkey;
	char block0[8], block1[8];
	int size, offset;

	int dec_size = enc_size - 7; // -8 bytes from seed +1 for ending null byte
	*decrypted = malloc(dec_size);

	bfkey = bfopen(salt, strlen(salt));

	size = enc_size;
	memcpy(block0, encrypted, 8);
	memcpy(block1,encrypted + 8, 8);
	offset = 0;
	while(size > 8) {
		BF_encrypt((unsigned int *)block0, bfkey);
		xor_bytes(block0, block0, block1, 8);
		size = size - 8;
		memcpy(*decrypted+offset, block0, size < 8 ? size : 8);
		offset = offset + 8;
		memcpy(block0, block1, 8);
		memcpy(block1, encrypted+offset+8, 8);
	}
	(*decrypted)[dec_size-1] = '\0';
	return;
}

/* parse vault file and initialize macro store */
int parse_vault(void) {
	char *encrypted, *decrypted, *salt;
	char *line, *temp, *temp_ptr;
	char *variable = NULL;
	char *value = NULL;
	int macros_found = 0;
	int enc_size = 0;

	if(read_raw_vault(&encrypted, &enc_size, &salt) != OK) {
		return ERROR;
	}

	decrypt_vault(&decrypted, encrypted, enc_size, salt);
	free(encrypted);

	macro_store = kvvec_create(0);
	if(!macro_store) {
		return ERROR;
	}

	line = strtok_r(decrypted, "\n", &temp);
	do {
		/* skip blank lines and comments */
		if(strlen(line) < 1)
			continue;
		if(line[0] == '#' || line[0] == '\x0' || line[0] == '\n' || line[0] == '\r')
			continue;
		strip(line);

		/* get the variable name */
		if ((temp_ptr = my_strtok(line, "=")) == NULL) {
			nm_log(NSLOG_CONFIG_ERROR, "Error: parse error in vault file '%s' at %s", vault_file, line);
			return ERROR;
		}
		variable = (char *)nm_strdup(temp_ptr);

		/* get the value */
		if ((temp_ptr = my_strtok(NULL, "\n")) == NULL) {
			nm_log(NSLOG_CONFIG_ERROR, "Error: parse error in vault file '%s' at %s", vault_file, line);
			return ERROR;
		}
		value = nm_strdup(temp_ptr);

		/* check for macro declarations */
		if (variable[0] == '$' && variable[strlen(variable) - 1] == '$') {
			/* $VAULTx$ macro declarations */
			if (strstr(variable, "$VAULT") == variable  && strlen(variable) > 6) {
				variable[strlen(variable) - 1] = '\0';
				kvvec_addkv_str(macro_store, strdup(variable+1), strdup(value));
				nm_free(variable);
				nm_free(value);
				macros_found++;
				continue;
			}
		}
		nm_free(variable);
		nm_free(value);
		nm_log(NSLOG_CONFIG_ERROR, "Error: parse error in vault file '%s' at %s", vault_file, line);
		return ERROR;

	} while ((line = strtok_r(NULL, "\n", &temp)) != NULL);
	free(decrypted);

	if(macros_found == 0) {
		nm_log(NSLOG_CONFIG_ERROR, "Error: no macros found in %s, wrong password?", vault_file);
		return ERROR;
	}

	return OK;
}

/* read master password from stdin (unless already set) and open vault */
int nebmodule_init(__attribute__((unused)) int flags, char *arg, nebmodule *handle) {
	neb_handle = (void *)handle;
	struct kvvec *global_store;

	/* parse module args */
	if(parse_args(arg) != OK)
		return ERROR;

	nm_log(NSLOG_INFO_MESSAGE, "vault module loaded wth vault %s", vault_file);

	global_store = get_global_store();

	/* try using master password from environment */
	if(master_password == NULL)
		master_password = getenv("NAEMON_VIM_MASTER_PASSWORD");

	if(master_password == NULL)
		master_password = kvvec_fetch_str_str(global_store, master_password_store_key);

	if(master_password == NULL) {
		printf("\n");
		master_password = getpass("Enter vault master password: ");
		strip(master_password);
		if(strlen(master_password) == 0) {
			nm_log(NSLOG_INFO_MESSAGE, "Error: no master password given");
			return ERROR;
		}
		kvvec_addkv_str(global_store, master_password_store_key, (char *)mkstr("%s", master_password));
	}

	if(parse_vault() != OK)
		return ERROR;

	event_broker_options = BROKER_EVERYTHING;
	neb_register_callback(NEBCALLBACK_VAULT_MACRO_DATA, neb_handle, 0, handle_vault_macro);

	return OK;
}

/* cleanup macro store */
int nebmodule_deinit(__attribute__((unused)) int flags, __attribute__((unused)) int reason) {
	kvvec_destroy(macro_store, KVVEC_FREE_ALL);
	return OK;
}
