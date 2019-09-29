#include "TlsUtilities.h"

#include <cassert>

#include <glog/logging.h>

#include "TlsConnection.h"

namespace network
{
bool SendTlsMessage(TlsConnection *connection, const std::string &message)
{
    assert(connection);
    size_t bytes_remaining = message.size();
    while (bytes_remaining > 0)
    {
        size_t bytes_written;
        int write_errno;
        bool write_succeeded = connection->Write(
            reinterpret_cast<const uint8_t *>(message.c_str()),
            bytes_remaining,
            &bytes_written,
            &write_errno);

        if (!write_succeeded)
        {
            if (write_errno != EWOULDBLOCK && write_errno != EAGAIN)
            {
                LOG(ERROR) << "Encountered error when writing to TLS connection: "
                           << strerror(write_errno);
                return false;
            }
        }

        bytes_remaining -= bytes_written;
    }

    return true;
}

bool ReadTlsMessage(
    TlsConnection *connection,
    uint8_t *read_buffer,
    size_t length,
    std::string *out_message)
{
    assert(connection);
    assert(read_buffer);
    assert(out_message);

    size_t bytes_remaining = length;

    while (bytes_remaining > 0)
    {
        size_t bytes_read;
        int read_errno;
        bool read_succeeded = connection->Read(
            read_buffer,
            bytes_remaining,
            &bytes_read,
            &read_errno);

        if (!read_succeeded)
        {
            if (read_errno != EWOULDBLOCK && read_errno != EAGAIN)
            {
                LOG(ERROR) << "Failed while reading from TLS connection: " << strerror(read_errno);
                return false;
            }
        }
        bytes_remaining -= bytes_read;
    }

    return true;
}
} // namespace network
