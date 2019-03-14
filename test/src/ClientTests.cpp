/**
 * @file ClientTests.cpp
 *
 * This module contains the unit tests of the SmtpAuth::Client class.
 *
 * © 2019 by Richard Walters
 */

#include <Base64/Base64.hpp>
#include <gtest/gtest.h>
#include <Sasl/Client/Mechanism.hpp>
#include <SmtpAuth/Client.hpp>
#include <string>
#include <vector>

namespace {

    /**
     * This is a mock of a SASL mechanism.  It's used to test the
     * SmtpAuth::Client class.
     */
    struct MockSaslMechansim
        : public Sasl::Client::Mechanism
    {
        // Sasl::Client::Mechanism

        virtual void SetCredentials(
            const std::string& credentials,
            const std::string& authenticationIdentity,
            const std::string& authorizationIdentity = ""
        ) override {
        }

        virtual std::string GetInitialResponse() override {
            return "PogChamp";
        }

        virtual std::string Proceed(const std::string& message) override {
            return "LetMeIn";
        }

        virtual bool Succeeded() override {
            return true;
        }

        virtual bool Faulted() override {
            return false;
        }
    };

}

/**
 * This is the test fixture for these tests, providing common
 * setup and teardown for each test.
 */
struct ClientTests
    : public ::testing::Test
{
    // Properties

    std::shared_ptr< MockSaslMechansim > mech = std::make_shared< MockSaslMechansim >();
    SmtpAuth::Client auth;
    Smtp::Client::MessageContext context;
    std::vector< std::string > messagesSent;
    bool done = false;
    bool success = false;

    // Methods

    void SendMessageDirectly(const std::string& message) {
        messagesSent.push_back(message);
    }

    void OnExtensionStageComplete(bool success) {
        done = true;
        this->success = success;
    }

    void SendGoAhead() {
        auth.GoAhead(
            std::bind(&ClientTests::SendMessageDirectly, this, std::placeholders::_1),
            std::bind(&ClientTests::OnExtensionStageComplete, this, std::placeholders::_1)
        );
    }

    // ::testing::Test

    virtual void SetUp() override {
        auth.Configure("FOOBAR", mech);
    }

    virtual void TearDown() override {
    }
};

TEST_F(ClientTests, IsExtraProtocolStageNeededHere_LeadingUpToReadyToSendFirstMessage) {
    context.protocolStage = Smtp::Client::ProtocolStage::Greeting;
    EXPECT_FALSE(auth.IsExtraProtocolStageNeededHere(context));
    context.protocolStage = Smtp::Client::ProtocolStage::HelloResponse;
    EXPECT_FALSE(auth.IsExtraProtocolStageNeededHere(context));
    context.protocolStage = Smtp::Client::ProtocolStage::Options;
    EXPECT_FALSE(auth.IsExtraProtocolStageNeededHere(context));
}

TEST_F(ClientTests, IsExtraProtocolStageNeededHere_ReadyToSend) {
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    EXPECT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
}

TEST_F(ClientTests, IsExtraProtocolStageNeededHere_SendingMessage) {
    context.protocolStage = Smtp::Client::ProtocolStage::DeclaringSender;
    EXPECT_FALSE(auth.IsExtraProtocolStageNeededHere(context));
    context.protocolStage = Smtp::Client::ProtocolStage::DeclaringRecipients;
    EXPECT_FALSE(auth.IsExtraProtocolStageNeededHere(context));
    context.protocolStage = Smtp::Client::ProtocolStage::SendingData;
    EXPECT_FALSE(auth.IsExtraProtocolStageNeededHere(context));
    context.protocolStage = Smtp::Client::ProtocolStage::AwaitingSendResponse;
    EXPECT_FALSE(auth.IsExtraProtocolStageNeededHere(context));
}

TEST_F(ClientTests, GoAhead) {
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    ASSERT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
    SendGoAhead();
    EXPECT_EQ(
        std::vector< std::string >({
            "AUTH FOOBAR " + Base64::Encode("PogChamp") + "\r\n"
        }),
        messagesSent
    );
}

TEST_F(ClientTests, HandleServerMessage) {
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    ASSERT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
    SendGoAhead();
    ASSERT_EQ(
        std::vector< std::string >({
            "AUTH FOOBAR " + Base64::Encode("PogChamp") + "\r\n"
        }),
        messagesSent
    );
    Smtp::Client::ParsedMessage parsedMessage;
    parsedMessage.code = 235;
    parsedMessage.last = true;
    parsedMessage.text = "authenticated";
    EXPECT_TRUE(
        auth.HandleServerMessage(
            context,
            parsedMessage
        )
    );
}

TEST_F(ClientTests, DoneAndSuccessForSuccessfulAuthentication) {
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    ASSERT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
    SendGoAhead();
    ASSERT_EQ(
        std::vector< std::string >({
            "AUTH FOOBAR " + Base64::Encode("PogChamp") + "\r\n"
        }),
        messagesSent
    );
    Smtp::Client::ParsedMessage parsedMessage;
    parsedMessage.code = 235;
    parsedMessage.last = true;
    parsedMessage.text = "authenticated";
    ASSERT_TRUE(
        auth.HandleServerMessage(
            context,
            parsedMessage
        )
    );
    EXPECT_TRUE(done);
    EXPECT_TRUE(success);
}

TEST_F(ClientTests, DoneAndNotSuccesForUnsuccessfulAuthentication) {
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    ASSERT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
    SendGoAhead();
    ASSERT_EQ(
        std::vector< std::string >({
            "AUTH FOOBAR " + Base64::Encode("PogChamp") + "\r\n"
        }),
        messagesSent
    );
    Smtp::Client::ParsedMessage parsedMessage;
    parsedMessage.code = 535;
    parsedMessage.last = true;
    parsedMessage.text = "Go away, you smell";
    ASSERT_TRUE(
        auth.HandleServerMessage(
            context,
            parsedMessage
        )
    );
    EXPECT_TRUE(done);
    EXPECT_FALSE(success);
}

TEST_F(ClientTests, NoExtraProtocolStageNeededAfterAuthentication) {
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    ASSERT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
    SendGoAhead();
    ASSERT_EQ(
        std::vector< std::string >({
            "AUTH FOOBAR " + Base64::Encode("PogChamp") + "\r\n"
        }),
        messagesSent
    );
    Smtp::Client::ParsedMessage parsedMessage;
    parsedMessage.code = 235;
    parsedMessage.last = true;
    parsedMessage.text = "authenticated";
    ASSERT_TRUE(
        auth.HandleServerMessage(
            context,
            parsedMessage
        )
    );
    ASSERT_TRUE(done);
    EXPECT_FALSE(auth.IsExtraProtocolStageNeededHere(context));
}
