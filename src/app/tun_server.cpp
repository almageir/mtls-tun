#include "tun_server.h"

#include <charconv>
#include <utility>

namespace mtls_tun {

    TunServer::TunServer(const ServerConf &conf, asynclog::LoggerFactory log_factory): signals_(ioc_)
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

        std::uint16_t port{0};
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

        logger_.info("server started...");

        start_accept();
    }

    void TunServer::start_accept() {
        tcp::socket socket{ioc_.get_executor()};
        acceptor_.async_accept(
            [this](const net::error_code& ec, tcp::socket socket) {
                const auto new_session = TunSession::create(
                    std::move(socket), ssl_ctx_, manager_, log_factory_,
                    conf_.target_host,
                    conf_.target_port,
                    conf_.tls_options.server_name);

                logger_.info(std::format("[{}] new session created", new_session->id()));

                if (!ec)
                    new_session->start();
                else
                    logger_.err(ec.message());

                start_accept();
            });
    }

    void TunServer::run() {
        ioc_.run();
    }

    void TunServer::configure_signals() {
        signals_.add(SIGINT);
        signals_.add(SIGTERM);
    }

    void TunServer::configure_tls(const TlsOptions &settings) {
        auto options = net::ssl::context::default_workarounds | net::ssl::context::no_tlsv1_1;

        if (settings.version == "1.3") {
            options |= net::ssl::context::no_tlsv1_2;
            SSL_CTX_set_min_proto_version(ssl_ctx_.native_handle(), TLS1_3_VERSION);
        } else {
            SSL_CTX_set_min_proto_version(ssl_ctx_.native_handle(), TLS1_2_VERSION);
        }

        ssl_ctx_.set_options(options);

        ssl_ctx_.load_verify_file(settings.ca_cert);
        ssl_ctx_.use_private_key_file(settings.private_key, net::ssl::context::pem);
        ssl_ctx_.use_certificate_file(settings.client_cert, net::ssl::context::pem);
    }

    void TunServer::start_wait_signals() {
        signals_.async_wait(
            [this](const net::error_code& ec, int /*signo*/) {
                if (ec)
                    logger_.err(ec.message());

                acceptor_.close();
                ioc_.stop();
            });
    }
}
