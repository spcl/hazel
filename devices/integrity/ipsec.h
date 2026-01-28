#ifndef SPDK_MODULE_BDEV_INTEGRITY_IPSEC_H
#define SPDK_MODULE_BDEV_INTEGRITY_IPSEC_H

#define IPSEC_MAX_WINDOW_SIZE 1024
#define IPSEC_ENABLED 1 // Set to 1 to enable IPsec functionality
#define NETWORK_FRESHNESS_PACKET_SIZE 6 // Size of the network freshness counter
#define NETWORK_FRESHNESS_TAG_SIZE 16 // Size of the network freshness field

uint64_t ipsec_get_send_counter(void);
void ipsec_authenticate_send(uint8_t *source);
uint64_t atomic_max(_Atomic uint64_t *counter, uint64_t value);
bool ipsec_verify_recv_hash(uint8_t *source);
bool ipsec_verify_recv_counter(uint64_t value);

#endif // SPDK_MODULE_BDEV_INTEGRITY_IPSEC_H