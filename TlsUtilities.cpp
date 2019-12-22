#include "TlsUtilities.h"

#include <cassert>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <memory>
#include <utility>

#include  <arpa/inet.h>

#include  <openssl/bio.h>
#include  <openssl/ssl.h>
#include  <openssl/err.h>

#include <glog/logging.h>

#include "TlsConnection.h"

namespace network
{

void InitOpenSslForProcess()
{
    ERR_load_BIO_strings(); 
    OpenSSL_add_all_algorithms(); 
    SSL_load_error_strings();
}

bool SendTlsMessage(TlsConnection *connection, const std::string &message)
{
    assert(connection);
    size_t bytes_remaining = message.size();
    while (bytes_remaining > 0)
    {
        size_t bytes_written;
        bool eof = false;
        int write_errno;
        bool write_succeeded = connection->Write(
            reinterpret_cast<const uint8_t *>(message.c_str()),
            bytes_remaining,
            &bytes_written,
            &eof,
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
        else if (eof)
        {
            return true;
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
    LOG(ERROR) << "TlsUtilities::ReadTlsMessage() -- call";

    assert(connection);
    assert(read_buffer);
    assert(out_message);

    size_t bytes_remaining = length;

    while (bytes_remaining > 0)
    {
        size_t bytes_read;
        bool eof = false;
        int read_errno;
        bool read_succeeded = connection->Read(
            read_buffer,
            bytes_remaining,
            &bytes_read,
            &eof,
            &read_errno);

        if (!read_succeeded)
        {
            if (read_errno != EWOULDBLOCK && read_errno != EAGAIN)
            {
                LOG(ERROR) << "Failed while reading from TLS connection: " << strerror(read_errno);
                return false;
            }

            LOG(ERROR) << "bozkurtus -- would block";
        }
        else if (eof)
        {
            LOG(ERROR) << "TlsUtilities::ReadTlsMessage() -- eof!";
            return true;
        }

        bytes_remaining -= bytes_read;

        LOG(ERROR) << "ReadTlsMessage() loop. bytes remaining: " << bytes_remaining
                   << ". bytes read: " << bytes_read;
    }

    LOG(ERROR) << "TlsUtilities::ReadTlsMessage() -- end";

    return true;
}

bool SendTlsData(
    TlsConnection *cxn,
    const uint8_t *data,
    size_t data_len)
{
    assert(cxn);
    assert(data);

    size_t bytes_remaining = data_len;
    while (bytes_remaining > 0)
    {
        size_t bytes_written;
        bool eof = false;
        int write_errno;
        bool write_succeeded = cxn->Write(
            data,
            bytes_remaining,
            &bytes_written,
            &eof,
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
        else if (eof)
        {
            return true;
        }

        bytes_remaining -= bytes_written;
    }

    return true;
}

bool ReadTlsData(
    TlsConnection *cxn,
    uint8_t *data,
    size_t data_len)
{
    assert(cxn);
    assert(data);

    size_t bytes_remaining = data_len;

    while (bytes_remaining > 0)
    {
        size_t bytes_read;
        bool eof = false;
        int read_errno;
        bool read_succeeded = cxn->Read(
            data,
            bytes_remaining,
            &bytes_read,
            &eof,
            &read_errno);

        if (!read_succeeded)
        {
            if (read_errno != EWOULDBLOCK && read_errno != EAGAIN)
            {
                LOG(ERROR) << "Failed while reading from TLS connection: " << strerror(read_errno);
                return false;
            }

            LOG(ERROR) << "bozkurtus -- would block";
        }
        else if (eof)
        {
            LOG(ERROR) << "TlsUtilities::ReadTlsMessage() -- eof!";
            return true;
        }

        bytes_remaining -= bytes_read;

        LOG(ERROR) << "ReadTlsMessage() loop. bytes remaining: " << bytes_remaining
                   << ". bytes read: " << bytes_read;
    }

    LOG(ERROR) << "TlsUtilities::ReadTlsMessage() -- end";

    return true;
}

bool SendTlsProtobufMessage(
    TlsConnection *cxn,
    uint8_t msg_type,
    google::protobuf::Message *msg,
    bool *out_cxn_closed)
{
    assert(cxn);
    assert(msg);

    /**
     *  Packet format: [type -- 1 byte] [length -- 4 bytes] [message -- length bytes]
     */

    if (!SendTlsData(cxn, &msg_type, 1))
    {
        LOG(ERROR) << "Failed to send msg type: " << static_cast<int>(msg_type);
        return false;
    }

    size_t msg_len = msg->ByteSizeLong();
    uint32_t msg_len_network_order = htonl(static_cast<uint32_t>(msg_len));
    if (!SendTlsData(cxn, reinterpret_cast<uint8_t *>(&msg_len_network_order), sizeof(msg_len_network_order)))
    {
        LOG(ERROR) << "Failed to send msg length: " << msg_len;
        return false;
    }

    std::unique_ptr<uint8_t[]> data_buffer{new uint8_t[msg_len]};
    msg->InternalSerializeWithCachedSizesToArray(true, data_buffer.get());

    if (!SendTlsData(cxn, data_buffer.get(), msg_len))
    {
        LOG(ERROR) << "Failed to send protbuf message body";
        return false;
    }
   
    return true; 
}

bool ReadTlsProtobufMessageHeader(
    TlsConnection *cxn,
    uint8_t *out_type,
    uint32_t *out_size)
{
    assert(cxn);
    assert(out_type);
    assert(out_size);

    /**
     *  Header format: [type -- 1 byte] [length -- 4 bytes]
     */
    assert(sizeof(*out_type) == 1);
    if (!ReadTlsData(cxn, out_type, sizeof(*out_type)))
    {
        LOG(ERROR) << "Failed to read protobuf message type";
        return false;
    }

    assert(sizeof(*out_size) == 4);
    if (!ReadTlsData(cxn, reinterpret_cast<uint8_t *>(out_size), sizeof(*out_size)))
    {
        LOG(ERROR) << "Failed to read protobuf message type";
        return false;
    }
    *out_size = ntohl(*out_size);

    return true;
}

} // namespace network
