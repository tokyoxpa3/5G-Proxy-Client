#include "ip_hash.h"

uint32_t ip_hash32(const ip_addr_t *ip) {
    uint32_t h = 2166136261u;   // FNV-1a offset basis
    for (int i = 0; i < 16; i++) {
        h ^= ip->ip[i];
        h *= 16777619u;         // FNV-1a prime
    }
    return h ^ (uint32_t)ip->family;
}
