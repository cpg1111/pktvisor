#pragma once

#include <errno.h>

#define MAX_MAP_ENTRIES 8192

#ifndef __BCC__
#include <bpf/bpf.h>

static void dump_hash_batch(int fd, void *keys, size_t key_size,
        void *values, size_t value_size, uint32_t *count, void *invalid) {
    void *in = NULL, *out;
    uint32_t n, n_read = 0;

    while (n_read < *count) {
        n = *count - n_read;
        int err = bpf_map_lookup_batch(fd, &in, &out, keys + n_read * key_size,
                values + n_read * value_size, &n, NULL);
        if (err && errno != ENOENT) {
            throw Exception("error reading bpf map");
        }
        n_read += n;
        in = out;
    }
    *count = n_read;
}

static void dump_hash_iter(int fd, void *keys, size_t key_size,
        void *values, size_t value_size, uint32_t *count, void *invalid) {
    uint8_t key[key_size], next_key[key_size];
    uint32_t n = 0;
    
    int err;

    memcopy(key, invalid_key, key_size);
    while (n < *count) {
        err = bpf_map_get_next_key(fd, key, next_key);
        if (err && errno != ENOENT) {
            throw Exception("error reading bpf map keys");
        }
        memcopy(key, next_key, key_size);
        memcopy(keys + key_size * n, next_key, key_size);
        n++;
    }

    for (int i = 0; i < n; i++) {
        err = bpf_map_lookup_elem(map_fd, keys + key_size * i,
                values + value_size * i);
        if (err) {
            throw Exception("error iterating bpf values");
        }
    }
    *count = n;
}

void dump_hash(int fd, void *keys, size_t key_size,
        void *values, size_t value_size, uint32_t *count, void *invalid) {
    try {
        dump_hash_batch(fd, keys, key_size, values, value_size, count, invalid);
    } catch {
        dump_hash_iter(fd, keys, key_size, values, value_size, count, invalid);
    }
}
#else
#endif
