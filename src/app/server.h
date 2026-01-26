
#ifndef MTLS_TUN_SERVER_H
#define MTLS_TUN_SERVER_H

#include "session.h"

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <charconv>

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
        explicit server(const server_conf& conf)
            : signals_(ioc_)
            , acceptor_{ioc_}
            , remote_host_(conf.target_host)
            , remote_service_(conf.target_port)
            , ssl_ctx_{conf.tls_options.version == "1.2" ? net::ssl::context::tlsv12_client : net::ssl::context::tlsv13_client}
        {
            configure_signals();
            start_wait_signals();
            configure_tls(conf.tls_options);

            uint16_t port{0};
            auto [_, ec] = std::from_chars(
                conf.listen_port.data(),
                conf.listen_port.data() + conf.listen_port.size(),
                port);
            if (ec != std::errc())
                throw std::runtime_error{"Bad listen port number"};

            const auto ep{tcp::endpoint(tcp::v4(), port)};
            acceptor_.open(ep.protocol());
            acceptor_.set_option(tcp::acceptor::reuse_address(true));
            acceptor_.bind(ep);
            acceptor_.listen();

            start_accept();
        }

        void start_accept()
        {
            auto new_session = session::create(ioc_, ssl_ctx_, manager_,
                remote_host_, remote_service_, server_name_);

            acceptor_.async_accept(
                new_session->socket(),
                [this, new_session](const net::error_code& ec) {
                          if (!ec)
                              new_session->start();
                          else
                              std::cout << ec.message() << std::endl;
                          start_accept();
                      });
        }

        void run()
        {
            ioc_.run();
        }

    private:
        void configure_signals()
        {
            signals_.add(SIGINT);
            signals_.add(SIGTERM);
        }

        void configure_tls(const tls_options &settings)
        {
            auto options = net::ssl::context::default_workarounds | net::ssl::context::no_tlsv1_1;

            if (settings.version == "1.3")
                options |= net::ssl::context::no_tlsv1_2;

            ssl_ctx_.set_options(options);

            ssl_ctx_.load_verify_file(settings.ca_cert);
            ssl_ctx_.use_private_key_file(settings.private_key, net::ssl::context::pem);
            ssl_ctx_.use_certificate_file(settings.client_cert, net::ssl::context::pem);
        }

        void start_wait_signals()
        {
            signals_.async_wait(
                [this](const net::error_code& ec, int /*signo*/) {
                          if (ec)
                              std::cout << ec.message() << std::endl;

                          acceptor_.close();
                          ioc_.stop();
                      });
        }

        net::io_context ioc_;
        net::signal_set signals_;
        tcp::acceptor acceptor_;
        session_manager manager_;
        std::string remote_host_;
        std::string remote_service_;
        std::string server_name_;
        net::ssl::context ssl_ctx_;
    };
}

#endif //MTLS_TUN_SERVER_H