#ifndef MTLS_TUN_SESSION_H
#define MTLS_TUN_SESSION_H

#include "manager.h"

#include <asynclog/scoped_logger.h>

#include <asio/ssl.hpp>
#include <asio/ip/tcp.hpp>

#include <memory>

namespace asynclog {
    class LoggerFactory;
}

using tcp = asio::ip::tcp;
namespace net = asio;

namespace mtls_tun
{
    using std::placeholders::_1;
    using std::placeholders::_2;

    class TunSession;
    using TunSessionPtr = std::shared_ptr<TunSession>;

    class TunSession
        : public Session
        , public std::enable_shared_from_this<TunSession>
    {
    public:
        ~TunSession() override;

        tcp::socket& socket() { return local_sock_; }

        static TunSessionPtr create(tcp::socket&& socket,
                                    net::ssl::context& ctx,
                                    SessionManager& mgr,
                                    const asynclog::LoggerFactory &log_factory,
                                    std::string_view remote_host,
                                    std::string_view remote_port,
                                    std::string_view server_name);

        void start();
        void stop() override;

        std::size_t id() const { return id_; }

    private:
        TunSession(tcp::socket&& socket,
                   net::ssl::context& ctx,
                   SessionManager& mgr,
                   asynclog::ScopedLogger&& logger,
                   std::string_view remote_host,
                   std::string_view remote_service,
                   std::string_view server_name);

        void close();
        //void close_ssl();

        bool verify_certificate(bool preverified, net::ssl::verify_context& ctx);
        void handshake();

        void do_resolve();
        void do_connect(const tcp::resolver::results_type& eps);

        void do_read_from_local();
        void do_read_from_remote();
        void do_write_to_remote(std::size_t bytes_transferred);
        void do_write_to_local(std::size_t bytes_transferred);

        static inline std::size_t g_scount = 0;
        static inline std::size_t id_source = 0;

        enum { max_buff_size = 0x4000 };
        using buffer_type = std::array<std::uint8_t, max_buff_size>;

        tcp::socket local_sock_;
        tcp::resolver resolver_;
        net::ssl::stream<tcp::socket> remote_sock_;
        SessionManager& manager_;
        asynclog::ScopedLogger logger_;
        std::size_t id_;
        bool tls_established_{false};

        std::string remote_host_;
        std::string remote_service_;
        std::string server_name_;
        std::string remote_ep_;
        std::string remote_resolved_ep_;

        std::string client_ep_;

        buffer_type local_buffer_{};
        buffer_type remote_buffer_{};
    };
}

#endif //MTLS_TUN_SESSION_H