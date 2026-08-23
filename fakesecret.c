/*
 * fakesecret.c - a drop-in stand-in for libsecret-1.so.0
 *
 * Bun's `Bun.secrets` API dlopen()s "libsecret-1.so.0" and resolves exactly
 * five symbols. The real libsecret forwards them over D-Bus to
 * org.freedesktop.secrets, which requires a keyring daemon. This shim
 * implements those five symbols against a plaintext file instead.
 *
 * NOT SECURE: secrets are stored unencrypted, readable by anything running
 * as this user. That is the explicit intent.
 *
 * Build:
 *   gcc -shared -fPIC -O2 -o libsecret-1.so.0 fakesecret.c
 * Use:
 *   LD_LIBRARY_PATH=/path/to/dir proton-drive ...
 *
 * Env:
 *   FAKESECRET_STORE  store file (default $HOME/.local/share/fake-secrets)
 *   FAKESECRET_DEBUG  set to 1 to trace calls on stderr
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

/* --- minimal glib/libsecret ABI, so we don't need the dev headers --- */

typedef int gboolean;
typedef char gchar;
typedef void GCancellable;
typedef void GHashTable;
typedef void SecretService;
typedef void GList;

typedef enum {
    SECRET_SCHEMA_ATTRIBUTE_STRING  = 0,
    SECRET_SCHEMA_ATTRIBUTE_INTEGER = 1,
    SECRET_SCHEMA_ATTRIBUTE_BOOLEAN = 2
} SecretSchemaAttributeType;

typedef struct {
    const gchar *name;
    SecretSchemaAttributeType type;
} SecretSchemaAttribute;

typedef struct {
    const gchar *name;
    unsigned int flags;
    SecretSchemaAttribute attributes[32];
    int reserved;
    void *reserved1, *reserved2, *reserved3, *reserved4;
    void *reserved5, *reserved6, *reserved7;
} SecretSchema;

typedef struct {
    unsigned int domain;
    int code;
    gchar *message;
} GError;

/* --- helpers --- */

static int dbg(void)
{
    const char *d = getenv("FAKESECRET_DEBUG");
    return d && *d && strcmp(d, "0") != 0;
}

static const char *store_path(void)
{
    static char path[4096];
    if (path[0])
        return path;

    const char *env = getenv("FAKESECRET_STORE");
    if (env && *env) {
        snprintf(path, sizeof path, "%s", env);
        return path;
    }

    const char *home = getenv("HOME");
    if (!home || !*home)
        home = "/tmp";
    snprintf(path, sizeof path, "%s/.local/share", home);
    mkdir(path, 0700);
    snprintf(path, sizeof path, "%s/.local/share/fake-secrets", home);
    return path;
}

/* Records are stored hex-encoded so keys and secrets can hold any byte. */
static char *hex_encode(const char *in)
{
    size_t n = strlen(in);
    char *out = malloc(n * 2 + 1);
    if (!out)
        return NULL;
    for (size_t i = 0; i < n; i++)
        sprintf(out + i * 2, "%02x", (unsigned char)in[i]);
    out[n * 2] = '\0';
    return out;
}

static char *hex_decode(const char *in)
{
    size_t n = strlen(in);
    if (n % 2)
        return NULL;
    char *out = malloc(n / 2 + 1);
    if (!out)
        return NULL;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned int b;
        if (sscanf(in + i * 2, "%2x", &b) != 1) {
            free(out);
            return NULL;
        }
        out[i] = (char)b;
    }
    out[n / 2] = '\0';
    return out;
}

/*
 * Build a lookup key from the schema name plus the varargs attribute list.
 * Attributes are sorted by name so that store and lookup agree even if the
 * caller passes them in a different order.
 */

typedef struct {
    char *name;
    char *value;
} Attr;

static int attr_cmp(const void *a, const void *b)
{
    return strcmp(((const Attr *)a)->name, ((const Attr *)b)->name);
}

static SecretSchemaAttributeType attr_type(const SecretSchema *schema, const char *name)
{
    if (!schema)
        return SECRET_SCHEMA_ATTRIBUTE_STRING;
    for (int i = 0; i < 32 && schema->attributes[i].name; i++)
        if (strcmp(schema->attributes[i].name, name) == 0)
            return schema->attributes[i].type;
    return SECRET_SCHEMA_ATTRIBUTE_STRING;
}

static char *build_key(const SecretSchema *schema, va_list args)
{
    Attr attrs[32];
    int n = 0;

    while (n < 32) {
        const char *name = va_arg(args, const char *);
        if (!name)
            break;

        char buf[64];
        const char *value;
        switch (attr_type(schema, name)) {
        case SECRET_SCHEMA_ATTRIBUTE_INTEGER:
            snprintf(buf, sizeof buf, "%d", va_arg(args, int));
            value = buf;
            break;
        case SECRET_SCHEMA_ATTRIBUTE_BOOLEAN:
            value = va_arg(args, int) ? "true" : "false";
            break;
        default:
            value = va_arg(args, const char *);
            if (!value)
                value = "";
            break;
        }

        attrs[n].name = strdup(name);
        attrs[n].value = strdup(value);
        n++;
    }

    qsort(attrs, n, sizeof attrs[0], attr_cmp);

    size_t len = 128;
    for (int i = 0; i < n; i++)
        len += strlen(attrs[i].name) + strlen(attrs[i].value) + 2;

    char *key = malloc(len);
    if (!key)
        return NULL;

    snprintf(key, len, "%s|", schema && schema->name ? schema->name : "");
    for (int i = 0; i < n; i++) {
        strcat(key, attrs[i].name);
        strcat(key, "=");
        strcat(key, attrs[i].value);
        strcat(key, ";");
        free(attrs[i].name);
        free(attrs[i].value);
    }

    if (dbg())
        fprintf(stderr, "[fakesecret] key: %s\n", key);
    return key;
}

/*
 * Rewrite the store, dropping any record matching hexkey. If hexval is
 * non-NULL a record for hexkey is appended. Returns 1 if a match was dropped.
 */
static int rewrite(const char *hexkey, const char *hexval)
{
    const char *path = store_path();
    char tmp[4200];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);

    FILE *out = fopen(tmp, "w");
    if (!out) {
        if (dbg())
            fprintf(stderr, "[fakesecret] cannot write %s: %s\n", tmp, strerror(errno));
        return 0;
    }
    fchmod(fileno(out), 0600);

    int found = 0;
    FILE *in = fopen(path, "r");
    if (in) {
        char *line = NULL;
        size_t cap = 0;
        while (getline(&line, &cap, in) > 0) {
            char *sp = strchr(line, ' ');
            if (!sp)
                continue;
            *sp = '\0';
            if (strcmp(line, hexkey) == 0) {
                found = 1;
                continue; /* drop the old record */
            }
            *sp = ' ';
            fputs(line, out);
        }
        free(line);
        fclose(in);
    }

    if (hexval)
        fprintf(out, "%s %s\n", hexkey, hexval);

    fclose(out);
    if (rename(tmp, path) != 0) {
        if (dbg())
            fprintf(stderr, "[fakesecret] rename failed: %s\n", strerror(errno));
        unlink(tmp);
        return 0;
    }
    return found;
}

static char *store_lookup(const char *hexkey)
{
    FILE *in = fopen(store_path(), "r");
    if (!in)
        return NULL;

    char *line = NULL, *result = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, in) > 0) {
        char *sp = strchr(line, ' ');
        if (!sp)
            continue;
        *sp = '\0';
        if (strcmp(line, hexkey) != 0)
            continue;

        char *val = sp + 1;
        val[strcspn(val, "\r\n")] = '\0';
        result = hex_decode(val);
        break;
    }
    free(line);
    fclose(in);
    return result;
}

/* --- the five symbols Bun resolves --- */

gchar *secret_password_lookup_sync(const SecretSchema *schema,
                                   GCancellable *cancellable,
                                   GError **error, ...)
{
    (void)cancellable;
    if (error)
        *error = NULL;

    va_list args;
    va_start(args, error);
    char *key = build_key(schema, args);
    va_end(args);
    if (!key)
        return NULL;

    char *hexkey = hex_encode(key);
    free(key);
    if (!hexkey)
        return NULL;

    char *val = store_lookup(hexkey);
    free(hexkey);

    if (dbg())
        fprintf(stderr, "[fakesecret] lookup -> %s\n", val ? "hit" : "miss");
    return val;
}

gboolean secret_password_store_sync(const SecretSchema *schema,
                                    const gchar *collection,
                                    const gchar *label,
                                    const gchar *password,
                                    GCancellable *cancellable,
                                    GError **error, ...)
{
    (void)collection;
    (void)label;
    (void)cancellable;
    if (error)
        *error = NULL;

    va_list args;
    va_start(args, error);
    char *key = build_key(schema, args);
    va_end(args);
    if (!key)
        return 0;

    char *hexkey = hex_encode(key);
    char *hexval = hex_encode(password ? password : "");
    free(key);
    if (!hexkey || !hexval) {
        free(hexkey);
        free(hexval);
        return 0;
    }

    rewrite(hexkey, hexval);
    free(hexkey);
    free(hexval);

    if (dbg())
        fprintf(stderr, "[fakesecret] store -> %s\n", store_path());
    return 1;
}

gboolean secret_password_clear_sync(const SecretSchema *schema,
                                    GCancellable *cancellable,
                                    GError **error, ...)
{
    (void)cancellable;
    if (error)
        *error = NULL;

    va_list args;
    va_start(args, error);
    char *key = build_key(schema, args);
    va_end(args);
    if (!key)
        return 0;

    char *hexkey = hex_encode(key);
    free(key);
    if (!hexkey)
        return 0;

    int found = rewrite(hexkey, NULL);
    free(hexkey);

    if (dbg())
        fprintf(stderr, "[fakesecret] clear -> %s\n", found ? "removed" : "absent");
    return found;
}

void secret_password_free(gchar *password)
{
    free(password);
}

/*
 * Only used for enumerating stored items. Returning an empty list keeps the
 * caller happy without us having to synthesise SecretItem objects.
 */
GList *secret_service_search_sync(SecretService *service,
                                  const SecretSchema *schema,
                                  GHashTable *attributes,
                                  int flags,
                                  GCancellable *cancellable,
                                  GError **error)
{
    (void)service;
    (void)schema;
    (void)attributes;
    (void)flags;
    (void)cancellable;
    if (error)
        *error = NULL;
    if (dbg())
        fprintf(stderr, "[fakesecret] search -> empty list\n");
    return NULL;
}
