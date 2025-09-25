#include "../common.h"
#include "cuckoo_hash_operations.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define TEST_ELEMENTS 50
#define MAX_KEY_LEN 16
#define MAX_VALUE_LEN 4

typedef struct {
    uint8_t data[MAX_KEY_LEN];
} test_key_t;

typedef struct {
    uint32_t value;
} test_value_t;

// Simple hash function for test keys
static uint32_t test_key_hash(const test_key_t *key) {
    uint32_t hash = 0xdeadbeef;
    for (int i = 0; i < MAX_KEY_LEN; i++) {
        hash = (hash * 31) + key->data[i];
    }
    return hash;
}

// Generate random test key
static void generate_test_key(test_key_t *key, int seed) {
    srand(seed);
    for (int i = 0; i < MAX_KEY_LEN; i++) {
        key->data[i] = rand() % 256;
    }
}

// Compare test keys
static int compare_test_keys(const test_key_t *key1, const test_key_t *key2) {
    return memcmp(key1->data, key2->data, MAX_KEY_LEN);
}

// Test case 1: Basic insert and lookup
static int test_basic_operations(struct cuckoo_hash *hash_table) {
    printf("Running basic insert/lookup test...\n");

    test_key_t test_key;
    test_value_t test_value;

    // Generate test key
    generate_test_key(&test_key, 12345);
    test_value.value = 42;

    // Convert to cuckoo hash format
    cuckoo_hash_key_t cuckoo_key;
    cuckoo_hash_value_t cuckoo_value;

    memcpy(&cuckoo_key, &test_key, sizeof(test_key_t));
    cuckoo_value = test_value.value;

    // Create parameters
    struct __cuckoo_hash_bfs_queue bfs_queue;
    struct cuckoo_hash_parameters params = {
        .hash_table = hash_table,
        .bfs_queue = &bfs_queue
    };

    // Insert the element
    int result = cuckoo_hash_update_elem(&params, &cuckoo_key, &cuckoo_value);
    if (result != 0) {
        printf("FAILED: Insert returned %d\n", result);
        return -1;
    }

    // Look up the element
    cuckoo_hash_value_t *lookup_value;
    result = cuckoo_hash_lookup_elem(&params, &cuckoo_key, &lookup_value);
    if (result != 0) {
        printf("FAILED: Lookup returned %d\n", result);
        return -1;
    }

    // Verify the value
    if (*lookup_value != test_value.value) {
        printf("FAILED: Value mismatch. Expected %d, got %d\n",
               test_value.value, *lookup_value);
        return -1;
    }

    printf("PASSED: Basic insert/lookup test\n");
    return 0;
}

// Test case 2: Multiple elements
static int test_multiple_elements(struct cuckoo_hash *hash_table) {
    printf("Running multiple elements test...\n");

    test_key_t keys[TEST_ELEMENTS];
    test_value_t values[TEST_ELEMENTS];

    struct __cuckoo_hash_bfs_queue bfs_queue;
    struct cuckoo_hash_parameters params = {
        .hash_table = hash_table,
        .bfs_queue = &bfs_queue
    };

    // Insert multiple elements
    for (int i = 0; i < TEST_ELEMENTS; i++) {
        generate_test_key(&keys[i], i + 1000);
        values[i].value = i + 100;

        cuckoo_hash_key_t cuckoo_key;
        cuckoo_hash_value_t cuckoo_value = values[i].value;

        memcpy(&cuckoo_key, &keys[i], sizeof(test_key_t));

        int result = cuckoo_hash_update_elem(&params, &cuckoo_key, &cuckoo_value);
        if (result != 0) {
            printf("FAILED: Insert element %d returned %d\n", i, result);
            return -1;
        }
    }

    // Verify all elements can be retrieved
    for (int i = 0; i < TEST_ELEMENTS; i++) {
        cuckoo_hash_key_t cuckoo_key;
        cuckoo_hash_value_t *lookup_value;

        memcpy(&cuckoo_key, &keys[i], sizeof(test_key_t));

        int result = cuckoo_hash_lookup_elem(&params, &cuckoo_key, &lookup_value);
        if (result != 0) {
            printf("FAILED: Lookup element %d returned %d\n", i, result);
            return -1;
        }

        if (*lookup_value != values[i].value) {
            printf("FAILED: Value mismatch for element %d. Expected %d, got %d\n",
                   i, values[i].value, *lookup_value);
            return -1;
        }
    }

    printf("PASSED: Multiple elements test (%d elements)\n", TEST_ELEMENTS);
    return 0;
}

// Test case 3: Update existing element
static int test_update_element(struct cuckoo_hash *hash_table) {
    printf("Running update element test...\n");

    test_key_t test_key;
    generate_test_key(&test_key, 99999);

    struct __cuckoo_hash_bfs_queue bfs_queue;
    struct cuckoo_hash_parameters params = {
        .hash_table = hash_table,
        .bfs_queue = &bfs_queue
    };

    cuckoo_hash_key_t cuckoo_key;
    cuckoo_hash_value_t cuckoo_value;

    memcpy(&cuckoo_key, &test_key, sizeof(test_key_t));

    // Insert initial value
    cuckoo_value = 111;
    int result = cuckoo_hash_update_elem(&params, &cuckoo_key, &cuckoo_value);
    if (result != 0) {
        printf("FAILED: Initial insert returned %d\n", result);
        return -1;
    }

    // Verify initial value
    cuckoo_hash_value_t *lookup_value;
    result = cuckoo_hash_lookup_elem(&params, &cuckoo_key, &lookup_value);
    if (result != 0 || *lookup_value != 111) {
        printf("FAILED: Initial verification failed\n");
        return -1;
    }

    // Update to new value
    cuckoo_value = 222;
    result = cuckoo_hash_update_elem(&params, &cuckoo_key, &cuckoo_value);
    if (result != 0) {
        printf("FAILED: Update returned %d\n", result);
        return -1;
    }

    // Verify updated value
    result = cuckoo_hash_lookup_elem(&params, &cuckoo_key, &lookup_value);
    if (result != 0 || *lookup_value != 222) {
        printf("FAILED: Update verification failed\n");
        return -1;
    }

    printf("PASSED: Update element test\n");
    return 0;
}

// Test case 4: Hash collisions and bucket distribution
static int test_hash_collisions(struct cuckoo_hash *hash_table) {
    printf("Running hash collision test...\n");

    struct __cuckoo_hash_bfs_queue bfs_queue;
    struct cuckoo_hash_parameters params = {
        .hash_table = hash_table,
        .bfs_queue = &bfs_queue
    };

    // Create keys that will likely collide in same bucket
    const int collision_test_count = 10;
    test_key_t keys[collision_test_count];

    for (int i = 0; i < collision_test_count; i++) {
        // Generate similar keys to increase collision probability
        generate_test_key(&keys[i], 50000 + i);
        // Make them more similar
        keys[i].data[0] = 0xAA;  // Same first byte
        keys[i].data[1] = i;      // Different second byte

        cuckoo_hash_key_t cuckoo_key;
        cuckoo_hash_value_t cuckoo_value = i + 300;

        memcpy(&cuckoo_key, &keys[i], sizeof(test_key_t));

        int result = cuckoo_hash_update_elem(&params, &cuckoo_key, &cuckoo_value);
        if (result != 0) {
            printf("FAILED: Insert collision test %d returned %d\n", i, result);
            return -1;
        }
    }

    // Verify all collision test elements
    for (int i = 0; i < collision_test_count; i++) {
        cuckoo_hash_key_t cuckoo_key;
        cuckoo_hash_value_t *lookup_value;

        memcpy(&cuckoo_key, &keys[i], sizeof(test_key_t));

        int result = cuckoo_hash_lookup_elem(&params, &cuckoo_key, &lookup_value);
        if (result != 0) {
            printf("FAILED: Lookup collision test %d returned %d\n", i, result);
            return -1;
        }

        if (*lookup_value != i + 300) {
            printf("FAILED: Value mismatch for collision test %d\n", i);
            return -1;
        }
    }

    printf("PASSED: Hash collision test (%d elements)\n", collision_test_count);
    return 0;
}

int main() {
    printf("Starting cuckoo hash operations tests...\n\n");

    // Initialize hash table memory
    struct cuckoo_hash hash_table;
    memset(&hash_table, 0, sizeof(hash_table));

    // Manually initialize the hash table since we don't have bpf_map_lookup_elem
    // Initialize the free slot list
    for (int i = 1; i < CUCKOO_HASH_KEY_SLOTS; i++) {
        __cuckoo_hash_enqueue_slot_back(&hash_table, i);
    }
    hash_table.initialized = 1;

    printf("Hash table initialized with %d slots\n", CUCKOO_HASH_KEY_SLOTS - 1);

    // Test cases
    int test_results[4] = {0};

    test_results[0] = test_basic_operations(&hash_table);
    test_results[1] = test_multiple_elements(&hash_table);
    test_results[2] = test_update_element(&hash_table);
    test_results[3] = test_hash_collisions(&hash_table);

    // Summary
    printf("\n=== TEST SUMMARY ===\n");
    int passed = 0;
    const char *test_names[] = {
        "Basic insert/lookup",
        "Multiple elements",
        "Update element",
        "Hash collisions"
    };

    for (int i = 0; i < 4; i++) {
        printf("%-20s: %s\n", test_names[i],
               test_results[i] == 0 ? "PASSED" : "FAILED");
        if (test_results[i] == 0) passed++;
    }

    printf("\nTotal: %d/4 tests passed\n", passed);

    if (passed == 4) {
        printf("🎉 All tests passed!\n");
        return 0;
    } else {
        printf("❌ Some tests failed!\n");
        return 1;
    }
} 