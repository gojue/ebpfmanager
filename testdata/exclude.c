/* This file tests rewriting constants from C compiled code.
 */

#include "common.h"

char __license[] __section("license") = "MIT";

struct map map_one __section("maps") = {
	.type        = 1,
	.key_size    = sizeof(unsigned int),
	.value_size  = sizeof(unsigned int),
	.max_entries = 1,
};

struct map map_two __section("maps") = {
	.type        = 1,
	.key_size    = sizeof(unsigned int),
	.value_size  = sizeof(unsigned int),
	.max_entries = 1,
};

__section("socket/map1") int access_map_one() {
	unsigned int key = 0;
	unsigned int *value = map_lookup_elem(&map_one, &key);
	if (!value) {
		return 0;
	}
	return *value;
}

__section("socket/map2") int access_map_two() {
	unsigned int key = 0;
	unsigned int *value = map_lookup_elem(&map_two, &key);
	if (!value) {
		return 0;
	}
	return *value;
}
