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
    struct MockSaslMechanism
        : public Sasl::Client::Mechanism
    {
        // Properties

        std::string initialResponse;
        std::string username;
        std::string password;
        bool wasReset = false;

        // Methods

        explicit MockSaslMechanism(const std::string& initialResponse)
            : initialResponse(initialResponse)
        {
        }

        // Sasl::Client::Mechanism

        virtual SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate SubscribeToDiagnostics(
            SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
            size_t minLevel = 0
        ) override {
            return []{};
        }

        virtual void Reset() override {
            wasReset = true;
        }

        virtual void SetCredentials(
            const std::string& credentials,
            const std::string& authenticationIdentity,
            const std::string& authorizationIdentity = ""
        ) override {
            password = credentials;
            username = authenticationIdentity;
        }

        virtual std::string GetInitialResponse() override {
            return initialResponse;
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

    std::shared_ptr< MockSaslMechanism > mech1 = std::make_shared< MockSaslMechanism >("PogChamp");
    std::shared_ptr< MockSaslMechanism > mech2 = std::make_shared< MockSaslMechanism >("FeelsBadMan");
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
        auth.Register("FOO", 1, mech1);
        auth.Register("BAR", 2, mech2);
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

TEST_F(ClientTests, IsExtraProtocolStageNeededHere_ReadyToSend_MechSupported) {
    auth.Configure("FOO");
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    EXPECT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
}

TEST_F(ClientTests, IsExtraProtocolStageNeededHere_ReadyToSend_NoMechSupported) {
    auth.Configure("SPAM");
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    EXPECT_FALSE(auth.IsExtraProtocolStageNeededHere(context));
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

TEST_F(ClientTests, GoAheadFoo) {
    auth.Configure("FOO");
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    ASSERT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
    SendGoAhead();
    EXPECT_EQ(
        std::vector< std::string >({
            "AUTH FOO " + Base64::Encode("PogChamp") + "\r\n"
        }),
        messagesSent
    );
}

TEST_F(ClientTests, GoAheadBar) {
    auth.Configure("BAR");
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    ASSERT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
    SendGoAhead();
    EXPECT_EQ(
        std::vector< std::string >({
            "AUTH BAR " + Base64::Encode("FeelsBadMan") + "\r\n"
        }),
        messagesSent
    );
}

TEST_F(ClientTests, GoAheadFooBar) {
    auth.Configure("FOO BAR");
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    ASSERT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
    SendGoAhead();
    EXPECT_EQ(
        std::vector< std::string >({
            "AUTH BAR " + Base64::Encode("FeelsBadMan") + "\r\n"
        }),
        messagesSent
    );
}

TEST_F(ClientTests, HandleServerMessage) {
    auth.Configure("FOO");
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    ASSERT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
    SendGoAhead();
    ASSERT_EQ(
        std::vector< std::string >({
            "AUTH FOO " + Base64::Encode("PogChamp") + "\r\n"
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
    auth.Configure("FOO");
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    ASSERT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
    SendGoAhead();
    ASSERT_EQ(
        std::vector< std::string >({
            "AUTH FOO " + Base64::Encode("PogChamp") + "\r\n"
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

TEST_F(ClientTests, HardFailureForUnsuccessfulAuthentication) {
    auth.Configure("FOO");
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    ASSERT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
    SendGoAhead();
    ASSERT_EQ(
        std::vector< std::string >({
            "AUTH FOO " + Base64::Encode("PogChamp") + "\r\n"
        }),
        messagesSent
    );
    Smtp::Client::ParsedMessage parsedMessage;
    parsedMessage.code = 535;
    parsedMessage.last = true;
    parsedMessage.text = "Go away, you smell";
    ASSERT_FALSE(
        auth.HandleServerMessage(
            context,
            parsedMessage
        )
    );
    EXPECT_FALSE(done);
}

TEST_F(ClientTests, NoExtraProtocolStageNeededAfterAuthentication) {
    auth.Configure("FOO");
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    ASSERT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
    SendGoAhead();
    ASSERT_EQ(
        std::vector< std::string >({
            "AUTH FOO " + Base64::Encode("PogChamp") + "\r\n"
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

TEST_F(ClientTests, SetCredentials) {
    auth.Configure("FOO BAR");
    auth.SetCredentials("hunter2", "alex");
    EXPECT_EQ("hunter2", mech1->password);
    EXPECT_EQ("alex", mech1->username);
    EXPECT_EQ("hunter2", mech2->password);
    EXPECT_EQ("alex", mech2->username);
}

TEST_F(ClientTests, AllMechsResetOnReset) {
    auth.Configure("FOO BAR");
    auth.Reset();
    EXPECT_TRUE(mech1->wasReset);
    EXPECT_TRUE(mech2->wasReset);
}

TEST_F(ClientTests, SecondAuthenticationAfterReset) {
    auth.Configure("FOO");
    context.protocolStage = Smtp::Client::ProtocolStage::ReadyToSend;
    (void)auth.IsExtraProtocolStageNeededHere(context);
    SendGoAhead();
    Smtp::Client::ParsedMessage parsedMessage;
    parsedMessage.code = 235;
    parsedMessage.last = true;
    parsedMessage.text = "authenticated";
    (void)auth.HandleServerMessage(
        context,
        parsedMessage
    );
    auth.Reset();
    EXPECT_TRUE(auth.IsExtraProtocolStageNeededHere(context));
}
