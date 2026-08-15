#ifndef JNI_BRIDGE_H
#define JNI_BRIDGE_H

void jni_attach_thread(void);
void jni_detach_thread(void);
int request_java_socket(const char *host, int port, int is_udp);
void release_java_socket(int fd);

#endif
