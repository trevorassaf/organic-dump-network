#include <gflags/gflags.h>
#include <glog/logging.h>

#include <TlsServerFactory.h>

DEFINE_string(message, "", "Message");

int main(int argc, char **argv)
{
    google::ParseCommandLineFlags(&argc, &argv, false);
    google::InitGoogleLogging(argv[0]);
    network::TlsServerFactory factory;

    LOG(INFO) << "Message: " << FLAGS_message;

    return EXIT_SUCCESS;
}
