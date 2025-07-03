#include "socks5_proxy.h"

int main() {
    Socks5Proxy proxy;
    if (!proxy.Initialize()) {
        printf("Failed to initialize proxy\n");
        return 1;
    }

    proxy.Run();
    return 0;
}