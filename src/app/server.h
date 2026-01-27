
#ifndef MTLS_TUN_SERVER_H
#define MTLS_TUN_SERVER_H

#include "session.h"

#include <asynclog/scoped_logger.h>
#include <asynclog/logger_factory.h>

#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ssl.hpp>
#include <asio/signal_set.hpp>

namespace mtls_tun
{
    using tcp = asio::ip::tcp;
    namespace net = asio;

    struct tls_options {
        std::string private_key;
        std::string client_cert;
        std::string ca_cert;
        std::string version;
        std::string server_name;
    };

    struct server_conf {
        std::string listen_port;
        std::string target_port;
        std::string target_host;
        tls_options tls_options;
    };

    class server
    {
    public:
        explicit server(const server_conf& conf, asynclog::LoggerFactory log_factory);

        void start_accept();
        void run();

    private:
        void configure_signals();
        void configure_tls(const tls_options &settings);
        void start_wait_signals();

        net::io_context ioc_;
        net::signal_set signals_;
        tcp::acceptor acceptor_;
        session_manager manager_;
        server_conf conf_;
        net::ssl::context ssl_ctx_;
        asynclog::LoggerFactory log_factory_;
        asynclog::ScopedLogger logger_;
    };
}

#endif //MTLS_TUN_SERVER_H