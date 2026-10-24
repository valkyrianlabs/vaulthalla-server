#include "platform/Durable.hpp"

#include <unistd.h>

namespace vh::platform::durable {

int sync(const int fd) noexcept { return ::fsync(fd); }

}
