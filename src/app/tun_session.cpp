#include "tun_session.h"

#include <asio.hpp>

#include <iostream>
#include <array>

#include <format>

#include "asynclog/logger_factory.h"

namespace {

    enum class RemoteAddrType : std::uint8_t {
        Invalid,
        Ip,
        Dns
    };

    RemoteAddrType get_remote_addr_type(std::string_view remote_host) {
        if (remote_host.empty())
            return RemoteAddrType::Invalid;

        net::error_code ec;
        auto addr = net::ip::make_address(remote_host, ec);

        if (!ec && (addr.is_v4() || addr.is_v6()))
            return RemoteAddrType::Ip;

        return RemoteAddrType::Dns;
    }

    std::string to_string(const net::error_code ec, const tcp::endpoint& rep)
    {
        if (ec)
            return std::format("remote_endpoint failed: {}", ec.message());

        return std::format("{}:{}", rep.address().to_string(), rep.port());
    }

    std::string ep_to_str(const tcp::socket& sock)
    {
        if (!sock.is_open())
            return "socket not opened";

        net::error_code ec;
        const tcp::endpoint rep = sock.remote_endpoint(ec);

        return to_string(ec, rep);
    }

    std::string ep_to_str(const net::ssl::stream<tcp::socket>& sock)
    {
        if (!sock.lowest_layer().is_open())
            return {"socket not opened"};

        net::error_code ec;
        const tcp::endpoint rep = sock.lowest_layer().remote_endpoint(ec);

        return to_string(ec, rep);
    }
}

namespace mtls_tun {

    TunSession::TunSession(tcp::socket&& socket,
                           net::ssl::context& ctx,
                           SessionManager& mgr,
                           asynclog::ScopedLogger&& logger,
                           std::string_view remote_host,
                           std::string_view remote_service,
                           std::string_view server_name)
        : local_sock_{std::move(socket)}
        , resolver_{local_sock_.get_executor()}
        , remote_sock_{local_sock_.get_executor(), ctx}
        , manager_{mgr}
        , logger_{std::move(logger)}
        , id_{id_source++}
        , remote_host_{remote_host}
        , remote_service_{remote_service}
        , server_name_{server_name}
    {
        remote_ep_ = remote_host_ + ':' + remote_service_;
        remote_sock_.set_verify_mode(net::ssl::verify_peer);
        remote_sock_.set_verify_callback(std::bind(&TunSession::verify_certificate, this, _1, _2));
    }

    TunSession::~TunSession()
    {
        auto message = std::format("[{}] connection closed, managed sessions: {}, detached sessions: {}", id_,
                manager_.ses_count(), --g_scount);
        logger_.info(message);
    }

    TunSessionPtr TunSession::create(tcp::socket&& socket,
                                     net::ssl::context &ctx,
                                     SessionManager &mgr,
                                     const asynclog::LoggerFactory &log_factory,
                                     std::string_view remote_host,
                                     std::string_view remote_port,
                                     std::string_view server_name)
    {
        return TunSessionPtr(new TunSession(std::move(socket),
                                            ctx,
                                            mgr,
                                            log_factory.create("Session"),
                                            remote_host,
                                            remote_port,
                                            server_name));
    }

    void TunSession::start() {
        manager_.join(shared_from_this());
        client_ep_ = ep_to_str(local_sock_);

        const std::string message = std::format("[{}] accepted connection from {}, managed sessions: {}, detached sessions: {}",
                                                id_,
                                                client_ep_,
                                                manager_.ses_count(),
                                                ++g_scount);
        logger_.info(message);

        do_resolve();
    }

    void TunSession::stop() {
        close();
    }

    void TunSession::close() {
        if (local_sock_.is_open()) {
            net::error_code ignored_ec;
            local_sock_.shutdown(net::socket_base::shutdown_both, ignored_ec);
            local_sock_.close();
        }

        if (remote_sock_.lowest_layer().is_open() && tls_established_) {
            remote_sock_.async_shutdown(
                [this, self{shared_from_this()}](const net::error_code &ec) {
                    if (ec && ec.category() == net::error::get_ssl_category())
                        if (ec != net::error::operation_aborted)
                            logger_.info(std::format("[{}] {} value: {}", id_, ec.message(), ec.value()));
                    remote_sock_.lowest_layer().close();
                });
            net::async_write(
                remote_sock_, net::null_buffers{},
                [this, self{shared_from_this()}](const net::error_code& ec, std::size_t trans_bytes) {
                    if (ec && ec.category() == net::error::get_ssl_category())
                        if (ec != net::error::operation_aborted)
                            logger_.info(std::format("[{}] {} value: {}", id_, ec.message(), ec.value()));
                    remote_sock_.lowest_layer().close();
                });
        } else {
            net::error_code ignored_ec;
            remote_sock_.lowest_layer().shutdown(net::socket_base::shutdown_both, ignored_ec);
            remote_sock_.lowest_layer().close();
        }
    }

    bool TunSession::verify_certificate(bool preverified, net::ssl::verify_context& ctx) {
        if (!preverified)
            logger_.err(
                std::format("[{}] verify error: {}", id_,
                            X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx.native_handle()))));

        return preverified;
    }

    void TunSession::handshake() {
        remote_sock_.async_handshake(
            net::ssl::stream_base::client,
            [this, self{shared_from_this()}](const net::error_code& ec) {
                if (!ec) {
                    tls_established_ = true;
                    do_read_from_local();
                    do_read_from_remote();
                } else {
                    logger_.info(std::format("[{}] Handshake failed: {}", id_, ec.message()));
                    manager_.leave(self);
                }
            });
    }

    void TunSession::do_resolve() {
        resolver_.async_resolve(
            remote_host_, remote_service_,
            [this, self{shared_from_this()}](const net::error_code& ec, const tcp::resolver::results_type& eps) {
                if (!ec) {
                    do_connect(eps);
                } else {
                    logger_.info(std::format("[{}] [{}] {}", id_, remote_ep_, ec.message()));
                    manager_.leave(self);
                }
            });
    }

    void TunSession::do_connect(const tcp::resolver::results_type& eps) {
        net::async_connect(
            remote_sock_.lowest_layer(), eps,
            [this, self{shared_from_this()}](const net::error_code& ec, const tcp::endpoint & /*ep*/) {
                remote_resolved_ep_ = std::format("({})", ep_to_str(remote_sock_));

                if (!ec) {
                    logger_.info(std::format("[{}] connection from {} to {}{} established",
                                             id_, client_ep_, remote_ep_, remote_resolved_ep_));

                    const auto remote_addr_type = get_remote_addr_type(remote_host_);

                    X509_VERIFY_PARAM* param = SSL_get0_param(remote_sock_.native_handle());

                    if (remote_addr_type == RemoteAddrType::Ip) {
                        const auto addr = remote_sock_.lowest_layer().remote_endpoint().address().to_v4().to_bytes();
                        X509_VERIFY_PARAM_set1_ip(param, addr.data(), 4);
                    } else if (remote_addr_type == RemoteAddrType::Dns) {
                        X509_VERIFY_PARAM_set1_host(param, remote_host_.c_str(), remote_host_.size());
                    } else {
                        logger_.err(std::format("[{}] bad target host name provided: {}", id_, remote_host_));
                        manager_.leave(self);
                        return;
                    }

                    if (!server_name_.empty()) {
                        if (!SSL_set_tlsext_host_name(remote_sock_.native_handle(), server_name_.c_str())) {
                            logger_.err(std::format("[{}] SNI setup error: {}", id_, server_name_));
                            manager_.leave(self);
                            return;
                        }
                    }

                    handshake();
                } else {
                    logger_.warn(std::format("[{}] connection error from {} to {} : {}",
                                             id_, client_ep_, remote_ep_, ec.message()));
                    manager_.leave(self);
                }
            });
    }

    void TunSession::do_read_from_local() {
        local_sock_.async_read_some(
            net::buffer(local_buffer_),
            [this, self{shared_from_this()}](const net::error_code& ec, std::size_t bytes_transferred) {
                if (!ec && bytes_transferred > 0) {
                    do_write_to_remote(bytes_transferred);
                } else {
                    manager_.leave(self);
                }
            });
    }

    void TunSession::do_read_from_remote() {
        remote_sock_.async_read_some(
            net::buffer(remote_buffer_),
            [this, self{shared_from_this()}](const net::error_code& ec, std::size_t bytes_transferred) {
                if (!ec && bytes_transferred > 0) {
                    do_write_to_local(bytes_transferred);
                } else {
                    manager_.leave(self);
                }
            });
    }

    void TunSession::do_write_to_remote(std::size_t bytes_transferred) {
        net::async_write(
            remote_sock_, net::buffer(local_buffer_.data(), bytes_transferred),
            [this, self{shared_from_this()}](const net::error_code& ec, std::size_t bytes_transferred) {
                if (!ec && bytes_transferred > 0) {
                    do_read_from_local();
                } else {
                    manager_.leave(self);
                }
            });
    }

    void TunSession::do_write_to_local(std::size_t bytes_transferred) {
        net::async_write(
            local_sock_, net::buffer(remote_buffer_.data(), bytes_transferred),
            [this, self{shared_from_this()}](const net::error_code& ec, std::size_t bytes_transferred) {
                if (!ec && bytes_transferred > 0) {
                    do_read_from_remote();
                } else {
                    manager_.leave(self);
                }
            });
    }
}
