#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <glob.h>
#include <naemon/naemon.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>

NEB_API_VERSION(CURRENT_NEB_API_VERSION);

enum {
	VAULT_FILE = 0,
	VAULT_PW,
	MAX_FILES,
	WARN_NO_MATCH
};

const char *module_opts[] = {
	[VAULT_FILE]    = "vault",
	[VAULT_PW]      = "password",
	[MAX_FILES]     = "max_files",
	[WARN_NO_MATCH] = "warn_no_match",
	NULL
};

const char *master_password_store_key = "master_password_store_key";
static void *neb_handle = NULL;
static char *vault_file = NULL;
static char *master_password = NULL;
static int max_files = 64;
static int warn_no_match = FALSE;
static struct kvvec *loaded_files = NULL;
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
	char *arg_value, *end;
	long number;
	arg = strtok(arg, " \t");
	while(arg != NULL) {
		switch (getsubopt (&arg, (char * const* restrict)module_opts, &arg_value)) {
			case VAULT_FILE:
				vault_file = arg_value;
				break;
			case VAULT_PW:
				master_password = arg_value;
				break;
			case MAX_FILES:
				errno = 0;
				number = arg_value ? strtol(arg_value, &end, 10) : 0;
				if(number < 1 || number > INT_MAX || errno || *end) {
					nm_log(NSLOG_INFO_MESSAGE, "Error: max_files must be a positive number");
					return ERROR;
				}
				max_files = number;
				break;
			case WARN_NO_MATCH:
				if(!arg_value || (strcmp(arg_value, "yes") && strcmp(arg_value, "no"))) {
					nm_log(NSLOG_INFO_MESSAGE, "Error: warn_no_match must be yes or no");
					return ERROR;
				}
				warn_no_match = !strcmp(arg_value, "yes");
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
	return OK;
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
int read_raw_vault(const char *vault_file, char **buffer, int *buffer_size, char **salt) {
	FILE *fp;
	char header[12];

	fp = fopen(vault_file, "rb");
	if(!fp) {
		nm_log(NSLOG_INFO_MESSAGE, "Error: cannot read vault file %s: %d - %s", vault_file, errno, strerror(errno));
		return ERROR;
	}

	fseek(fp , 0L , SEEK_END);
	*buffer_size = ftell(fp) - 20; // 12 bytes vimcrypt header, 8 byte salt
	rewind(fp);

	if(1 != fread(header , 12, 1 , fp) || strncmp("VimCrypt~", header, 9) != 0) {
		nm_log(NSLOG_INFO_MESSAGE, "Error: file %s is not a vim crypted file.", vault_file);
		fclose(fp);
		return ERROR;
	}
	if(strncmp("03!", header + 9, 3) != 0) {
		nm_log(NSLOG_INFO_MESSAGE, "Error: %s uses unsupported crypt method, only blowfish2 is supported.", vault_file);
		fclose(fp);
		return ERROR;
	}
	if(*buffer_size < 8) { // 8 byte seed
		nm_log(NSLOG_INFO_MESSAGE, "Error: vault file %s is truncated.", vault_file);
		fclose(fp);
		return ERROR;
	}

	/* read 8 bytes of salt */
	*salt = nm_malloc(8);
	if(1 != fread(*salt , 8, 1 , fp)) {
		nm_log(NSLOG_INFO_MESSAGE, "Error: cannot read vault file %s: %d - %s", vault_file, errno, strerror(errno));
		fclose(fp);
		free(*salt);
		return ERROR;
	}

	/* copy the remaining file into the buffer */
	*buffer = nm_malloc(*buffer_size);
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
	char block[8];
	int size;

	/* the first 8 bytes are the seed, the plaintext is 8 bytes shorter */
	*decrypted = nm_malloc(enc_size - 7);

	bfkey = bfopen(salt, 8);

	/* cfb: each plaintext block is the encrypted previous ciphertext block xor the current one */
	for(int offset = 8; offset < enc_size; offset += 8) {
		memcpy(block, encrypted + offset - 8, 8);
		BF_encrypt((unsigned int *)block, bfkey);
		size = enc_size - offset < 8 ? enc_size - offset : 8;
		xor_bytes(*decrypted + offset - 8, block, encrypted + offset, size);
	}
	(*decrypted)[enc_size - 8] = '\0';
}

static int parse_vault_file(const char *vault_file);

/* escape the glob() special characters, so the path only matches itself */
static char *glob_escape(const char *path) {
	char *escaped = nm_malloc(2 * strlen(path) + 1), *p = escaped;

	for(; *path != '\0'; path++) {
		if(strchr("\\*?[]{}", *path))
			*p++ = '\\';
		*p++ = *path;
	}
	*p = '\0';
	return escaped;
}

/* parse all files matching an include/include_dir directive, relative to the including file */
static int parse_include(const char *vault_file, const char *directive, const char *value) {
	char *dir, *base, *rel, *pattern;
	glob_t matches;
	int rc, result = OK;

	/* include_dir=X includes all *.cfg files in X */
	nm_asprintf(&rel, "%s%s", value, strcmp(directive, "include_dir") ? "" : "/*.cfg");
	/* only the value is a pattern, the directory of the including file is literal */
	dir = nspath_absolute_dirname(vault_file, NULL);
	base = glob_escape(dir);
	pattern = nspath_absolute(rel, base);

	rc = glob(pattern, GLOB_BRACE | GLOB_ERR, NULL, &matches);
	if(rc == 0) {
		for(size_t i = 0; i < matches.gl_pathc && result == OK; i++)
			result = parse_vault_file(matches.gl_pathv[i]);
	} else if(rc == GLOB_NOMATCH && strpbrk(rel, "*?[{")) {
		/* wildcards are optional */
		if(warn_no_match)
			nm_log(NSLOG_INFO_MESSAGE, "Warning: %s=%s in vault file %s matches no files", directive, value, vault_file);
	} else {
		nm_log(NSLOG_CONFIG_ERROR, "Error: %s=%s in vault file %s: %s", directive, value, vault_file, rc == GLOB_NOMATCH ? "no such file" : strerror(errno));
		result = ERROR;
	}

	globfree(&matches);
	free(pattern);
	free(base);
	free(dir);
	free(rel);
	return result;
}

/* parse a single vault file into the macro store */
static int parse_vault_file(const char *vault_file) {
	char *encrypted, *decrypted, *salt, *canonical;
	char *line, *temp, *variable, *value;
	struct key_value *kv;
	int lines_found = 0;
	int enc_size = 0;
	int result = OK;

	/* every file only once, and not more than max_files */
	if((canonical = realpath(vault_file, NULL)) == NULL) {
		nm_log(NSLOG_INFO_MESSAGE, "Error: cannot read vault file %s: %d - %s", vault_file, errno, strerror(errno));
		return ERROR;
	}
	if(kvvec_fetch(loaded_files, canonical, strlen(canonical)) != NULL) {
		nm_log(NSLOG_CONFIG_ERROR, "Error: vault file %s is included more than once (duplicate or loop)", canonical);
		free(canonical);
		return ERROR;
	}
	if(loaded_files->kv_pairs >= max_files) {
		nm_log(NSLOG_CONFIG_ERROR, "Error: cannot include vault file %s, max_files=%d reached", canonical, max_files);
		free(canonical);
		return ERROR;
	}
	kvvec_addkv_str(loaded_files, canonical, "");

	if(read_raw_vault(vault_file, &encrypted, &enc_size, &salt) != OK) {
		return ERROR;
	}

	decrypt_vault(&decrypted, encrypted, enc_size, salt);
	free(encrypted);
	free(salt);

	for(line = strtok_r(decrypted, "\n", &temp); line != NULL; line = strtok_r(NULL, "\n", &temp)) {
		/* skip blank lines and comments */
		strip(line);
		if(line[0] == '\0')
			continue;
		lines_found++;
		if(line[0] == '#')
			continue;

		/* split into variable and value */
		variable = line;
		value = strchr(line, '=');
		if(value == NULL || value[1] == '\0') {
			nm_log(NSLOG_CONFIG_ERROR, "Error: parse error in vault file '%s' at %s", vault_file, line);
			result = ERROR;
			break;
		}
		*value++ = '\0';

		/* $VAULTx$ macro declarations, a later definition replaces an earlier one */
		if(strncmp(variable, "$VAULT", 6) == 0 && strlen(variable) > 6 && variable[strlen(variable) - 1] == '$') {
			variable[strlen(variable) - 1] = '\0';
			if((kv = kvvec_fetch(macro_store, variable + 1, strlen(variable + 1))) != NULL) {
				free(kv->value);
				kv->value = strdup(value);
				kv->value_len = strlen(value);
			} else {
				kvvec_addkv_str(macro_store, strdup(variable + 1), strdup(value));
			}
			continue;
		}

		/* include directives, like macros without blanks around the = */
		if((strcmp(variable, "include") && strcmp(variable, "include_dir")) || isspace((unsigned char)value[0])) {
			nm_log(NSLOG_CONFIG_ERROR, "Error: parse error in vault file '%s' at %s", vault_file, line);
			result = ERROR;
			break;
		}
		if(parse_include(vault_file, variable, value) != OK) {
			result = ERROR;
			break;
		}
	}
	free(decrypted);

	if(result == OK && lines_found == 0) {
		nm_log(NSLOG_CONFIG_ERROR, "Error: no macros found in %s, wrong password?", vault_file);
		return ERROR;
	}

	return result;
}

/* parse vault file and its includes and initialize macro store, all or nothing */
int parse_vault(void) {
	char *path = nspath_absolute(vault_file, NULL);
	int result = ERROR;

	macro_store = kvvec_create(0);
	loaded_files = kvvec_create(0);
	if(macro_store != NULL && loaded_files != NULL)
		result = parse_vault_file(path);

	kvvec_destroy(loaded_files, KVVEC_FREE_KEYS);
	loaded_files = NULL;
	free(path);
	if(result != OK) {
		kvvec_destroy(macro_store, KVVEC_FREE_ALL);
		macro_store = NULL;
	}
	return result;
}

/* keep an entered master password for module reloads, the copy lives as long as naemon */
static void remember_password(const char *password) {
	kvvec_addkv_str(get_global_store(), master_password_store_key, nm_strdup(password));
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
		remember_password(master_password);
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
