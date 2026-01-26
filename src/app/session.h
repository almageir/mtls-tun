#ifndef MTLS_TUN_SESSION_H
#define MTLS_TUN_SESSION_H

#include "manager.h"

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <iostream>
#include <array>

using tcp = asio::ip::tcp;
namespace net = asio;

namespace
{
    using std::placeholders::_1;
    using std::placeholders::_2;

    size_t g_scount = 0;

    enum : std::int32_t { eRemote, eLocal };
    std::string ep_to_str(const tcp::socket& sock, std::int32_t dir)
    {
        if (!sock.is_open())
            return "socket not opened";

        net::error_code ec;
        const auto& rep = (dir == eRemote) ? sock.remote_endpoint(ec) : sock.local_endpoint(ec);
        if (ec)
        {
            std::ostringstream ss;
            ss << ((dir == eRemote) ? "remote_endpoint failed: " : "local_endpoint failed: ");
            ss << ec.message();
            return ss.str();
        }

        return { rep.address().to_string() + ":" + std::to_string(rep.port()) };
    }

    std::string ep_to_str(const net::ssl::stream<tcp::socket>& sock, std::int32_t dir)
    {
        if (!sock.lowest_layer().is_open())
            return "socket not opened";

        net::error_code ec;
        const auto& rep = (dir == eRemote) ? sock.lowest_layer().remote_endpoint(ec) : sock.lowest_layer().local_endpoint(ec);
        if (ec)
        {
            std::stringstream ss;
            ss << ((dir == eRemote) ? "remote_endpoint failed: " : "local_endpoint failed: ");
            ss << ec.message();
            return ss.str();
        }

        return { rep.address().to_string() + ":" + std::to_string(rep.port()) };
    }
}

namespace mtls_tun
{
    class session
        : public session_base
        , public std::enable_shared_from_this<session>
    {
        enum { max_buff_size = 0x4000 };
        using buffer_type = std::array<std::uint8_t, max_buff_size>;

        tcp::resolver resolver_;
        tcp::socket local_sock_;
        net::ssl::stream<tcp::socket> remote_sock_;
        session_manager &manager_;

        std::string remote_host_;
        std::string remote_service_;
        std::string server_name_;
        std::string remote_ep_;
        std::string remote_resolved_ep_;

        std::string client_ep_;

        buffer_type local_buffer_{};
        buffer_type remote_buffer_{};

        session(net::io_context& ios,
                net::ssl::context& ctx,
                session_manager& mgr,
                std::string_view remote_host,
                std::string_view remote_service,
                std::string_view server_name)
            : resolver_{ios}
            , local_sock_{ios}
            , remote_sock_{ios, ctx}
            , manager_{mgr}
            , remote_host_{remote_host}
            , remote_service_{remote_service}
            , server_name_{server_name}
        {
            remote_ep_ = remote_host_ + ':' + remote_service_;
            remote_sock_.set_verify_mode(net::ssl::verify_peer);
            remote_sock_.set_verify_callback(std::bind(&session::verify_certificate, this, _1, _2));
        }

    public:
        ~session() override
        {
            std::cout
            << "connection from "
            << client_ep_ << " to " << remote_ep_ << remote_resolved_ep_
            << " closed, sescnt: " << manager_.ses_count() << ", scnt: " << --g_scount << std::endl;

        }

        using pointer = std::shared_ptr<session>;

        tcp::socket & socket()
        {
            return local_sock_;
        }

        static pointer create(net::io_context &io_context,
                              net::ssl::context &ctx,
                              session_manager &mgr,
                              std::string_view remote_host,
                              std::string_view remote_port,
                              std::string_view server_name)
        {
            return pointer(new session(io_context, ctx, mgr, remote_host, remote_port, server_name));
        }

        void start()
        {
            manager_.join(shared_from_this());
            client_ep_ = ep_to_str(local_sock_, eRemote);
            std::cout
                    << "accepted connection from " << client_ep_
                    << " , sescnt: " << manager_.ses_count() << ", scnt: " << ++g_scount << std::endl;
            do_resolve();
        }

        void stop() override
        {
            close();
        }

    private:
        void close()
        {
            net::error_code ignored_ec;
            if (local_sock_.is_open()) {
                local_sock_.shutdown(net::socket_base::shutdown_both, ignored_ec);
                local_sock_.close();
            }

            if (remote_sock_.lowest_layer().is_open()) {
                net::error_code ec;
                remote_sock_.lowest_layer().cancel(ec);
                remote_sock_.async_shutdown(
                    [this, self{shared_from_this()}](const net::error_code &ec) {
                        if (ec && ec.category() == net::error::get_ssl_category()) {
                            if (ec != net::error::operation_aborted/* && ec != net::error::bad_descriptor*/) {
                                std::string msg = ec.message();
                                std::cout << msg << " value: " << ec.value() << std::endl;
                            }
                        }
                        remote_sock_.lowest_layer().close();
                    });
                net::async_write(
                    remote_sock_, net::null_buffers{},
                    [this, self{shared_from_this()}](const net::error_code &ec, std::size_t trans_bytes) {
                        if (ec && ec.category() == net::error::get_ssl_category()) {
                            if (ec != net::error::operation_aborted/* && ec != net::error::bad_descriptor*/) {
                                std::string msg = ec.message();
                                std::cout << msg << " value: " << ec.value() << std::endl;
                            }
                        }
                        remote_sock_.lowest_layer().close();
                    });
            }
        }

        void close_ssl()
        {
            if (remote_sock_.lowest_layer().is_open()) {
                net::error_code ec;
                remote_sock_.lowest_layer().cancel(ec);
                remote_sock_.async_shutdown(
                    [this, self{shared_from_this()}](const net::error_code &ec) {
                        if (ec) {
                            if (ec != net::error::operation_aborted && ec != net::error::bad_descriptor) {
                                std::string msg = ec.message();
                                std::cout << msg << " value: " << ec.value() << std::endl;
                            }
                        }
                        remote_sock_.lowest_layer().close();
                        if (local_sock_.is_open())
                            local_sock_.cancel();
                    });
            }
        }

        bool verify_certificate(bool preverified, net::ssl::verify_context &ctx)
        {
            return preverified;
        }

        void handshake()
        {
            //std::cout << "start handshake with: " << remote_resolved_ep_ << std::endl;
            remote_sock_.async_handshake(
                net::ssl::stream_base::client,
                [this, self{shared_from_this()}](const net::error_code &error) {
                    if (!error) {
                        //std::cout << "handshake ok: " << remote_resolved_ep_ << std::endl;
                        do_read_from_local();
                        do_read_from_remote();
                    } else {
                        std::cout << "Handshake failed: " << error.message() << "\n";
                        manager_.leave(shared_from_this());
                    }
                });
        }

        void do_resolve()
        {
            resolver_.async_resolve(
                remote_host_, remote_service_,
                [this, self{shared_from_this()}](const net::error_code &ec, const tcp::resolver::results_type &eps) {
                    if (!ec) {
                        do_connect(eps);
                    } else {
                        std::cout << '[' << remote_ep_ << "] " << ec.message() << std::endl;
                        manager_.leave(shared_from_this());
                    }
                });
        }

        void do_connect(const tcp::resolver::results_type &eps)
        {
            net::async_connect(
                remote_sock_.lowest_layer(), eps,
                [this, self{shared_from_this()}](const net::error_code &ec, const tcp::endpoint & /*ep*/) {
                    remote_resolved_ep_ = '(' + ep_to_str(remote_sock_, eRemote) + ')';
                    std::cout << "connection from " << client_ep_ << " to "
                            << remote_ep_ << remote_resolved_ep_ << " established\n";
                    if (!ec) {
                        if (!server_name_.empty()) {
                            if (!SSL_set_tlsext_host_name(remote_sock_.native_handle(), server_name_.c_str()))
                                throw std::runtime_error("SNI setup error");
                        }
                        handshake();
                    } else {
                        std::cout << ec.message() << std::endl;
                        manager_.leave(shared_from_this());
                    }
                });
        }

        void do_read_from_local()
        {
            local_sock_.async_read_some(
                net::buffer(local_buffer_),
                [this, self{shared_from_this()}](const net::error_code &ec, std::size_t bytes_transferred) {
                    if (!ec && bytes_transferred > 0) {
                        do_write_to_remote(bytes_transferred);
                    } else {
                        manager_.leave(shared_from_this());
                    }
                });
        }

        void do_read_from_remote()
        {
            remote_sock_.async_read_some(
                net::buffer(remote_buffer_),
                [this, self{shared_from_this()}](const net::error_code &ec, std::size_t bytes_transferred) {
                    if (!ec && bytes_transferred > 0) {
                        do_write_to_local(bytes_transferred);
                    } else {
                        manager_.leave(shared_from_this());
                    }
                });
        }

        void do_write_to_remote(std::size_t bytes_transferred)
        {
            net::async_write(
                remote_sock_, net::buffer(local_buffer_.data(), bytes_transferred),
                [this, self{shared_from_this()}](const net::error_code &ec, std::size_t bytes_transferred) {
                    if (!ec && bytes_transferred > 0) {
                        do_read_from_local();
                    } else {
                        manager_.leave(shared_from_this());
                    }
                });
        }

        void do_write_to_local(std::size_t bytes_transferred)
        {
            net::async_write(
                local_sock_, net::buffer(remote_buffer_.data(), bytes_transferred),
                [this, self{shared_from_this()}](const net::error_code &ec, std::size_t bytes_transferred) {
                    if (!ec && bytes_transferred > 0) {
                        do_read_from_remote();
                    } else {
                        manager_.leave(shared_from_this());
                    }
                });
        }
    };
}

#endif //MTLS_TUN_SESSION_H