#include "server.h"

#include <charconv>
#include <utility>

namespace mtls_tun {

    server::server(const server_conf &conf, asynclog::LoggerFactory log_factory): signals_(ioc_)
        , acceptor_{ioc_}
        , conf_{conf}
        , ssl_ctx_{
            conf.tls_options.version == "1.2"
                ? net::ssl::context::tlsv12_client
                : net::ssl::context::tlsv13_client
        }
        , log_factory_{std::move(log_factory)}
        , logger_{log_factory_.create("Server")}
    {
        configure_signals();
        start_wait_signals();
        configure_tls(conf_.tls_options);

        uint16_t port{0};
        auto [_, ec] = std::from_chars(
            conf_.listen_port.data(),
            conf_.listen_port.data() + conf_.listen_port.size(),
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

    void server::start_accept() {
        tcp::socket socket{ioc_.get_executor()};
        acceptor_.async_accept(
            [this](const net::error_code& ec, tcp::socket socket) {
                logger_.info("create new session");
                auto new_session = session::create(
                    std::move(socket), ssl_ctx_, manager_, log_factory_,
                    conf_.target_host,
                    conf_.target_port,
                    conf_.tls_options.server_name);

                if (!ec)
                    new_session->start();
                else
                    logger_.err(ec.message());
                start_accept();
            });
    }

    void server::run() {
        ioc_.run();
    }

    void server::configure_signals() {
        signals_.add(SIGINT);
        signals_.add(SIGTERM);
    }

    void server::configure_tls(const tls_options &settings) {
        auto options = net::ssl::context::default_workarounds | net::ssl::context::no_tlsv1_1;

        if (settings.version == "1.3")
            options |= net::ssl::context::no_tlsv1_2;

        ssl_ctx_.set_options(options);

        ssl_ctx_.load_verify_file(settings.ca_cert);
        ssl_ctx_.use_private_key_file(settings.private_key, net::ssl::context::pem);
        ssl_ctx_.use_certificate_file(settings.client_cert, net::ssl::context::pem);
    }

    void server::start_wait_signals() {
        signals_.async_wait(
            [this](const net::error_code& ec, int /*signo*/) {
                if (ec)
                    logger_.err(ec.message());

                acceptor_.close();
                ioc_.stop();
            });
    }
}
