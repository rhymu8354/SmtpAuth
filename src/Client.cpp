/**
 * @file Client.cpp
 *
 * This module contains the implementation of the SmtpAuth::Client class.
 *
 * © 2019 by Richard Walters
 */

#include <Base64/Base64.hpp>
#include <functional>
#include <SmtpAuth/Client.hpp>
#include <sstream>

namespace SmtpAuth {

    /**
     * This contains the private properties of a Client instance.
     */
    struct Client::Impl {
        // Properties

        /**
         * This is the name that the SMTP server recognizes for the
         * chosen authentication mechanism.
         */
        std::string mechName;

        /**
         * This is the implementation of the authentication mechanism
         * to be used.
         */
        std::shared_ptr< Sasl::Client::Mechanism > mechImpl;

        /**
         * This flag is set once the authentication exchange is complete,
         * whether or not it was successful.
         */
        bool done = false;

        /**
         * This is a function the extension can call to send
         * data directly to the SMTP server.
         */
        std::function< void(const std::string& data) > onSendMessage;

        /**
         * This is a function the extension can call to let the
         * SMTP client know that the current message failed to be
         * sent, and the protocol should go back to the "ready to
         * send" stage.
         */
        std::function< void() > onSoftFailure;

        /**
         * This is a function the extension can call to let the
         * SMTP client know that the custom procotol stage is
         * complete, and the client may proceed to the next stage.
         */
        std::function< void() > onStageComplete;

        // Method

        /**
         * Handle the fact that the authentication stage is complete.
         */
        void OnDone() {
            done = true;
            onStageComplete();
        }
    };

    Client::~Client() noexcept = default;
    Client::Client(Client&& other) noexcept = default;
    Client& Client::operator=(Client&& other) noexcept = default;

    Client::Client()
        : impl_(new Impl)
    {
    }

    void Client::Configure(
        const std::string& mechName,
        std::shared_ptr< Sasl::Client::Mechanism > mechImpl
    ) {
        impl_->mechName = mechName;
        impl_->mechImpl = mechImpl;
    }

    bool Client::IsExtraProtocolStageNeededHere(
        const Smtp::Client::MessageContext& context
    ) {
        return (
            !impl_->done
            && (context.protocolStage == Smtp::Client::ProtocolStage::ReadyToSend)
        );
    }

    void Client::GoAhead(
        std::function< void(const std::string& data) > onSendMessage,
        std::function< void() > onSoftFailure,
        std::function< void() > onStageComplete
    ) {
        impl_->onSendMessage = onSendMessage;
        impl_->onSoftFailure = onSoftFailure;
        impl_->onStageComplete = onStageComplete;
        const auto initialResponse = impl_->mechImpl->GetInitialResponse();
        std::ostringstream messageBuilder;
        messageBuilder << "AUTH " << impl_->mechName;
        if (!initialResponse.empty()) {
            messageBuilder << ' ' << Base64::Encode(initialResponse);
        }
        messageBuilder << "\r\n";
        onSendMessage(messageBuilder.str());
    }

    bool Client::HandleServerMessage(
        const Smtp::Client::MessageContext& context,
        const Smtp::Client::ParsedMessage& message
    ) {
        switch (message.code) {
            case 235: { // successfully authenticated
                impl_->OnDone();
            } break;

            case 334: { // continue request
                const auto response = impl_->mechImpl->Proceed(
                    message.text
                );
                std::ostringstream messageBuilder;
                messageBuilder << Base64::Encode(response);
                messageBuilder << "\r\n";
                impl_->onSendMessage(messageBuilder.str());
            } break;

            default: { // something bad happened; FeelsBadMan
                impl_->onSoftFailure();
                impl_->OnDone();
            } break;
        }
        return true;
    }

}
