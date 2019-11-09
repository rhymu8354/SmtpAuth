/**
 * @file Client.cpp
 *
 * This module contains the implementation of the SmtpAuth::Client class.
 *
 * © 2019 by Richard Walters
 */

#include <Base64/Base64.hpp>
#include <functional>
#include <map>
#include <SmtpAuth/Client.hpp>
#include <sstream>
#include <StringExtensions/StringExtensions.hpp>
#include <vector>

namespace {

    /**
     * This holds information about one registered SASL mechanism.
     */
    struct Mechanism {
        /**
         * This is the implementation of the authentication mechanism
         * to be used.
         */
        std::shared_ptr< Sasl::Client::Mechanism > impl;

        /**
         * This is used to select from multiple supported mechanisms,
         * where the one with the highest rank is selected.
         */
        int rank = 0;
    };

}

namespace SmtpAuth {

    /**
     * This contains the private properties of a Client instance.
     */
    struct Client::Impl {
        // Properties

        /**
         * This is a helper object used to generate and publish
         * diagnostic messages.
         */
        SystemAbstractions::DiagnosticsSender diagnosticsSender;

        /**
         * This contains all registered SASL mechanisms, keyed by the name that
         * the SMTP server recognizes for the mechanism.
         */
        std::map< std::string, Mechanism > mechs;

        /**
         * These are the names of the SASL mechanisms that the SMTP server
         * supports.
         */
        std::vector< std::string > supportedMechs;

        /**
         * This is the mechanism selected for use in the authentication.
         */
        std::shared_ptr< Sasl::Client::Mechanism > selectedMech;

        /**
         * This is the name that the SMTP server recognizes for the selected
         * mechanism.
         */
        std::string selectedMechName;

        /**
         * This is the function to call to unsubscribe from receiving
         * diagnostic messages from the selected SASL mechanism.
         */
        SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate selectedMechDiagnosticsUnsubscribeDelegate;

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
         * SMTP client know that the custom procotol stage is
         * complete.  The parameter indicates whether or not the
         * client may proceed to the next stage.
         */
        std::function< void(bool success) > onStageComplete;

        // Methods

        /**
         * This is the default constructor of the structure
         */
        Impl()
            : diagnosticsSender("SmtpAuth")
        {
        }

        /**
         * Handle the fact that the authentication stage is complete.
         */
        void OnDone(bool success) {
            done = true;
            onStageComplete(success);
        }

        /**
         * Find the highest ranked SASL mechanism registered that is also
         * supported by the SMTP server.
         */
        void SelectBestSupportedMechanism() {
            if (selectedMechDiagnosticsUnsubscribeDelegate != nullptr) {
                selectedMechDiagnosticsUnsubscribeDelegate();
            }
            int selectedRank = 0;
            selectedMech = nullptr;
            for (const auto& supportedMech: supportedMechs) {
                const auto mechsEntry = mechs.find(supportedMech);
                if (mechsEntry == mechs.end()) {
                    continue;
                }
                if (
                    (selectedMech == nullptr)
                    || (mechsEntry->second.rank > selectedRank)
                ) {
                    selectedMechName = supportedMech;
                    selectedMech = mechsEntry->second.impl;
                    selectedRank = mechsEntry->second.rank;
                }
            }
            if (selectedMech != nullptr) {
                selectedMechDiagnosticsUnsubscribeDelegate = selectedMech->SubscribeToDiagnostics(
                    diagnosticsSender.Chain()
                );
            }
        }
    };

    Client::~Client() noexcept = default;
    Client::Client(Client&& other) noexcept = default;
    Client& Client::operator=(Client&& other) noexcept = default;

    Client::Client()
        : impl_(new Impl)
    {
    }

    SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate Client::SubscribeToDiagnostics(
        SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
        size_t minLevel
    ) {
        return impl_->diagnosticsSender.SubscribeToDiagnostics(delegate, minLevel);
    }

    void Client::Register(
        const std::string& mechName,
        int rank,
        std::shared_ptr< Sasl::Client::Mechanism > mechImpl
    ) {
        auto& mech = impl_->mechs[mechName];
        mech.impl = mechImpl;
        mech.rank = rank;
    }

    void Client::SetCredentials(
        const std::string& credentials,
        const std::string& authenticationIdentity,
        const std::string& authorizationIdentity
    ) {
        for (auto& mech: impl_->mechs) {
            mech.second.impl->SetCredentials(
                credentials,
                authenticationIdentity,
                authorizationIdentity
            );
        }
    }

    void Client::Configure(const std::string& parameters) {
        impl_->supportedMechs = StringExtensions::Split(parameters, ' ');
    }

    void Client::Reset() {
        for (auto& mech: impl_->mechs) {
            mech.second.impl->Reset();
        }
        impl_->done = false;
    }

    bool Client::IsExtraProtocolStageNeededHere(
        const Smtp::Client::MessageContext& context
    ) {
        if (
            impl_->done
            || (context.protocolStage != Smtp::Client::ProtocolStage::ReadyToSend)
        ) {
            return false;
        }
        impl_->SelectBestSupportedMechanism();
        return (impl_->selectedMech != nullptr);
    }

    void Client::GoAhead(
        std::function< void(const std::string& data) > onSendMessage,
        std::function< void(bool success) > onStageComplete
    ) {
        impl_->onSendMessage = onSendMessage;
        impl_->onStageComplete = onStageComplete;
        const auto initialResponse = impl_->selectedMech->GetInitialResponse();
        std::ostringstream messageBuilder;
        messageBuilder << "AUTH " << impl_->selectedMechName;
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
                impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
                    0,
                    "S: %d%c%s",
                    message.code,
                    message.last ? ' ' : '-',
                    message.text.c_str()
                );
                impl_->OnDone(true);
            } break;

            case 334: { // continue request
                const auto decodedText = Base64::Decode(message.text);
                impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
                    0,
                    "S: %d%c%s",
                    message.code,
                    message.last ? ' ' : '-',
                    decodedText.c_str()
                );
                const auto response = impl_->selectedMech->Proceed(
                    decodedText
                );
                std::ostringstream messageBuilder;
                messageBuilder << Base64::Encode(response);
                messageBuilder << "\r\n";
                impl_->onSendMessage(messageBuilder.str());
            } break;

            default: { // something bad happened; FeelsBadMan
                impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
                    SystemAbstractions::DiagnosticsSender::Levels::WARNING,
                    "S: %d%c%s",
                    message.code,
                    message.last ? ' ' : '-',
                    message.text.c_str()
                );
            } return false;
        }
        return true;
    }

}
