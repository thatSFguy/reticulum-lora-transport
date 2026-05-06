#include "Storage.h"

#include <Adafruit_LittleFS.h>
#include <InternalFileSystem.h>

using namespace Adafruit_LittleFS_Namespace;

namespace rlr { namespace storage {

namespace {
bool s_mounted = false;
}

bool init() {
    if (s_mounted) return true;
    s_mounted = InternalFS.begin();
    return s_mounted;
}

bool exists(const char* path) {
    if (!s_mounted) return false;
    return InternalFS.exists(path);
}

int load_file(const char* path, uint8_t* buf, size_t bufsize) {
    if (!s_mounted || !InternalFS.exists(path)) return -1;
    File f = InternalFS.open(path, FILE_O_READ);
    if (!f) return -1;
    int n = f.read(buf, bufsize);
    f.close();
    return n;
}

bool save_file(const char* path, const uint8_t* data, size_t len) {
    if (!s_mounted) return false;
    // Truncating-write: opening FILE_O_WRITE on Adafruit_LittleFS
    // appends rather than truncates. Remove first to get clean
    // overwrite semantics.
    if (InternalFS.exists(path)) InternalFS.remove(path);
    File f = InternalFS.open(path, FILE_O_WRITE);
    if (!f) return false;
    size_t written = f.write(data, len);
    f.close();
    return written == len;
}

bool remove_file(const char* path) {
    if (!s_mounted || !InternalFS.exists(path)) return false;
    return InternalFS.remove(path);
}

}} // namespace rlr::storage
