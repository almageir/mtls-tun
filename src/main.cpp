#include "app/server.h"

#include <asynclog/log_manager.h>
#include <asynclog/scoped_logger.h>
#include <asynclog/logger_factory.h>
#include <cliap/cliap.h>

#include <iostream>


std::optional<mtls_tun::server_conf> parse_command_line_arguments(int argc, char* argv[])
{
    using cliap::Arg;
    cliap::ArgParser argParser;

    argParser
        .add_parameter(Arg("h,help").flag().description("Show help message"))
        .add_parameter(Arg("l,listen-port").required().set_default("2080").description("tls forwarder listen port number"))
        .add_parameter(Arg("t,target-port").required().set_default("8443").description("tls forwarder target port number"))
        .add_parameter(Arg("d,target-host").required().set_default("127.0.0.1").description("tls forwarder target host"))
        .add_parameter(Arg("p,private-key").required().description("private key file path (pem format)"))
        .add_parameter(Arg("s,client-cert").required().description("client certificate file path (pem format)"))
        .add_parameter(Arg("c,ca-cert").required().description("CA certificate file path (pem format)"))
        .add_parameter(Arg("n,server-name").description("TLS server name (SNI)"))
        .add_parameter(Arg("v,tls-version").set_default("1.3").description("TLS protocol version [1.2 or 1.3]"));

    const auto err_msg = argParser.parse(argc, argv);
    if (argParser.arg("h").is_parsed()) {
        argParser.print_help();
        return std::nullopt;
    }

    if (err_msg.has_value()) {
        std::cout << *err_msg << std::endl;
        argParser.print_help();
        return std::nullopt;
    }

    mtls_tun::server_conf srv_conf{};
    srv_conf.tls_options.private_key = argParser.arg("p").get_value_as_str();
    srv_conf.tls_options.client_cert = argParser.arg("s").get_value_as_str();
    srv_conf.tls_options.ca_cert = argParser.arg("c").get_value_as_str();
    if (argParser.arg("n").is_parsed())
        srv_conf.tls_options.version = argParser.arg("n").get_value_as_str();
    srv_conf.tls_options.version = argParser.arg("v").get_value_as_str();
    srv_conf.listen_port = argParser.arg("l").get_value_as_str();
    srv_conf.target_host = argParser.arg("d").get_value_as_str();
    srv_conf.target_port = argParser.arg("t").get_value_as_str();

    return srv_conf;
}

int main(int argc, char* argv[])
{
    namespace asl = asynclog;

    auto log_backend = std::make_shared<asl::LogManager>();
    log_backend->open(asl::LogMode::Console | asl::LogMode::File, "trace.log");

    asl::LoggerFactory log_factory(log_backend);

    auto logger = log_factory.create("Application");

    const auto conf = parse_command_line_arguments(argc, argv);
    if (!conf.has_value()) {
        logger.info("Program finished...");
        return 0;
    }

#ifdef _WIN32
    std::locale::global(std::locale(""));
#endif

    try {
        mtls_tun::server srv(conf.value(), log_factory);
        srv.run();
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        logger.info(ex.what());
    }

    return 0;
}
