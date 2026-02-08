#ifndef MTLS_TUN_MANAGER_H
#define MTLS_TUN_MANAGER_H

#include <set>
#include <memory>

namespace mtls_tun
{
    class Session {
    public:
        virtual ~Session() = default;
        virtual void stop() {
        }
    };

    using SessionPtr = std::shared_ptr<Session>;

    class SessionManager {
    public:
        void join(SessionPtr ses) {
            sessions_.insert(std::move(ses));
        }

        void leave(const SessionPtr &ses) {
            ses->stop();
            sessions_.erase(ses);
        }

        std::size_t ses_count() const { return sessions_.size(); }

    private:
        std::set<SessionPtr> sessions_;
    };
}

#endif //MTLS_TUN_MANAGER_H