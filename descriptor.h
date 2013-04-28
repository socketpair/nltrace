#ifndef NLTRACE_DESCRIPTOR_H
#define NLTRACE_DESCRIPTOR_H
struct descriptor;

int compare_descriptors (const void *a, const void *b);

struct descriptor *descriptor_alloc (int fd, int family, int protocol);
struct descriptor *descriptor_alloc_detect_proc (int fd, const char *description);
struct descriptor *descriptor_alloc_detect_live (int fd);

void descriptor_destroy (struct descriptor *descriptor);
int descriptor_get_family (const struct descriptor *descriptor);
int descriptor_get_protocol (const struct descriptor *descriptor);

void descriptor_handle_send (struct descriptor *descriptor, unsigned char *data, size_t length);
void descriptor_handle_recv (struct descriptor *descriptor, unsigned char *data, size_t length);

#endif
