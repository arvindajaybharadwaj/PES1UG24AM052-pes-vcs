// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include <errno.h>
#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out)
{
    for (int i = 0; i < HASH_SIZE; i++)
    {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out)
{
    if (strlen(hex) < HASH_HEX_SIZE)
        return -1;
    for (int i = 0; i < HASH_SIZE; i++)
    {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1)
            return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out)
{
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size)
{
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id)
{
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out)
{
    // TODO: Implement
    const char *type_str;

    switch (type)

    {

    case OBJ_BLOB:

        type_str = "blob";

        break;

    case OBJ_TREE:

        type_str = "tree";

        break;

    case OBJ_COMMIT:

        type_str = "commit";

        break;

    default:

        return -1;
    }

    // ---- Build header ----

    char header[64];

    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);

    if (header_len < 0 || header_len >= (int)sizeof(header))

        return -1;

    header[header_len] = '\0';

    header_len += 1; // include null terminator

    // ---- Build full object ----

    size_t total_len = header_len + len;

    unsigned char *obj_buf = malloc(total_len);

    if (!obj_buf)

        return -1;

    memcpy(obj_buf, header, header_len);

    memcpy(obj_buf + header_len, data, len);

    // ---- Compute hash ----

    ObjectID id;

    compute_hash(obj_buf, total_len, &id);

    // ---- Deduplication ----

    if (object_exists(&id))

    {

        if (id_out)

            *id_out = id;

        free(obj_buf);

        return 0;
    }

    // ---- Build path ----

    char path[512];

    object_path(&id, path, sizeof(path));

    // Extract directory path

    char dir[512];

    char *slash = strrchr(path, '/');

    if (!slash)

    {

        free(obj_buf);

        return -1;
    }

    size_t dir_len = slash - path;

    if (dir_len >= sizeof(dir))

    {

        free(obj_buf);

        return -1;
    }

    memcpy(dir, path, dir_len);

    dir[dir_len] = '\0';

    // ---- Create directory if needed ----

    if (mkdir(dir, 0755) < 0 && errno != EEXIST)

    {

        free(obj_buf);

        return -1;
    }

    // ---- Temp file (unique) ----

    char tmp_path[600];

    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp_%d", dir, getpid());

    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);

    if (fd < 0)

    {

        free(obj_buf);

        return -1;
    }

    // ---- Robust write (handle partial writes) ----

    ssize_t written = 0;

    while (written < (ssize_t)total_len)

    {

        ssize_t n = write(fd, obj_buf + written, total_len - written);

        if (n <= 0)

        {

            close(fd);

            unlink(tmp_path);

            free(obj_buf);

            return -1;
        }

        written += n;
    }

    // ---- fsync file ----

    if (fsync(fd) < 0)

    {

        close(fd);

        unlink(tmp_path);

        free(obj_buf);

        return -1;
    }

    close(fd);

    // ---- Atomic rename ----

    if (rename(tmp_path, path) < 0)

    {

        unlink(tmp_path);

        free(obj_buf);

        return -1;
    }

    // ---- fsync directory ----

    int dir_fd = open(dir, O_DIRECTORY | O_RDONLY);

    if (dir_fd >= 0)

    {

        fsync(dir_fd);

        close(dir_fd);
    }

    if (id_out)

        *id_out = id;

    free(obj_buf);

    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out)
{
    // TODO: Implement
    char path[512];

    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");

    if (!f)

        return -1;

    // ---- Get file size ----

    if (fseek(f, 0, SEEK_END) != 0)

    {

        fclose(f);

        return -1;
    }

    long file_size = ftell(f);

    if (file_size <= 0)

    {

        fclose(f);

        return -1;
    }

    rewind(f);

    unsigned char *buf = malloc(file_size);

    if (!buf)

    {

        fclose(f);

        return -1;
    }

    if (fread(buf, 1, file_size, f) != (size_t)file_size)

    {

        free(buf);

        fclose(f);

        return -1;
    }

    fclose(f);

    // ---- Integrity check ----

    ObjectID computed;

    compute_hash(buf, file_size, &computed);

    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0)

    {

        free(buf);

        return -1;
    }

    // ---- Parse header ----

    void *nul = memchr(buf, '\0', file_size);

    if (!nul)

    {

        free(buf);

        return -1;
    }

    size_t header_len = (unsigned char *)nul - buf;

    char type_str[16];

    size_t size;

    if (sscanf((char *)buf, "%15s %zu", type_str, &size) != 2)

    {

        free(buf);

        return -1;
    }

    ObjectType type;

    if (strcmp(type_str, "blob") == 0)

        type = OBJ_BLOB;

    else if (strcmp(type_str, "tree") == 0)

        type = OBJ_TREE;

    else if (strcmp(type_str, "commit") == 0)

        type = OBJ_COMMIT;

    else

    {

        free(buf);

        return -1;
    }

    // ---- Extract data ----

    unsigned char *data_start = (unsigned char *)nul + 1;

    size_t data_len = file_size - (header_len + 1);

    if (data_len != size)

    {

        free(buf);

        return -1;
    }

    void *out = malloc(data_len);

    if (!out)

    {

        free(buf);

        return -1;
    }

    memcpy(out, data_start, data_len);

    *type_out = type;

    *data_out = out;

    *len_out = data_len;

    free(buf);

    return 0;
}
