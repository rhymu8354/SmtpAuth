#pragma once

/**
 * @file Client.hpp
 *
 * This module declares the SmtpAuth::Client class.
 *
 * © 2019 by Richard Walters
 */

#include <memory>
#include <Sasl/Client/Mechanism.hpp>
#include <Smtp/Client.hpp>
#include <SystemAbstractions/DiagnosticsSender.hpp>

namespace SmtpAuth {

    /**
     * This class implements the client portion of the SMTP Service Extension
     * for Authentication [RFC 4954](https://tools.ietf.org/html/rfc4954)
     * protocol.
     */
    class Client
        : public Smtp::Client::Extension
    {
        // Lifecycle management
    public:
        ~Client() noexcept;
        Client(const Client&) = delete;
        Client(Client&&) noexcept;
        Client& operator=(const Client&) = delete;
        Client& operator=(Client&&) noexcept;

        // Public methods
    public:
        /**
         * This is the default constructor.
         */
        Client();

        /**
         * This method forms a new subscription to diagnostic
         * messages published by the class.
         *
         * @param[in] delegate
         *     This is the function to call to deliver messages
         *     to the subscriber.
         *
         * @param[in] minLevel
         *     This is the minimum level of message that this subscriber
         *     desires to receive.
         *
         * @return
         *     A function is returned which may be called
         *     to terminate the subscription.
         */
        SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate SubscribeToDiagnostics(
            SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
            size_t minLevel = 0
        );

        /**
         * This adds an authentication mechanism to be used if supported.
         *
         * @param[in] mechName
         *     This is the name that the SMTP server recognizes for the
         *     chosen authentication mechanism.
         *
         * @param[in] rank
         *     This is used to select from multiple supported mechanisms,
         *     where the one with the highest rank is selected.
         *
         * @param[in] mechImpl
         *     This is the implementation of the authentication mechanism
         *     to be used.
         */
        void Register(
            const std::string& mechName,
            int rank,
            std::shared_ptr< Sasl::Client::Mechanism > mechImpl
        );

        /**
         * Set the identities and credentials to use in the authentication.
         *
         * @param[in] credentials
         *     This is the information specific to the mechanism that
         *     the client uses to authenticate (e.g. certificate, ticket,
         *     password, etc.)
         *
         * @param[in] authenticationIdentity
         *     This is the identity to to associate with the credentials
         *     in the authentication.
         *
         * @param[in] authorizationIdentity
         *     This is the identity to "act as" in the authentication.
         *     If empty, the client is requesting to act as the identity the
         *     server associates with the client's credentials.
         */
        void SetCredentials(
            const std::string& credentials,
            const std::string& authenticationIdentity,
            const std::string& authorizationIdentity = ""
        );

        // Smtp::Client::Extension
    public:
        virtual void Configure(const std::string& parameters) override;
        virtual void Reset() override;
        virtual bool IsExtraProtocolStageNeededHere(
            const Smtp::Client::MessageContext& context
        ) override;
        virtual void GoAhead(
            std::function< void(const std::string& data) > onSendMessage,
            std::function< void(bool success) > onStageComplete
        ) override;
        virtual bool HandleServerMessage(
            const Smtp::Client::MessageContext& context,
            const Smtp::Client::ParsedMessage& message
        ) override;

        // Private properties
    private:
        /**
         * This is the type of structure that contains the private
         * properties of the instance.  It is defined in the implementation
         * and declared here to ensure that it is scoped inside the class.
         */
        struct Impl;

        /**
         * This contains the private properties of the instance.
         */
        std::shared_ptr< Impl > impl_;
    };

}
