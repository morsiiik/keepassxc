#include "PKCS11Key.h"
#include <QDataStream>
#include <iostream>

QUuid PKCS11Key::UUID("390cede5-1a9f-425b-aee5-b2bdab6b1e2c");

PKCS11Key::PKCS11Key()
    : Key(UUID)
{
}

void PKCS11Key::sign_data(const std::string& file_path, Botan::PKCS11::secure_string Pin)
{
    try {
        Botan::PKCS11::Module module(file_path);
        std::vector<Botan::PKCS11::SlotId> Slots = Botan::PKCS11::Slot::get_available_slots(module, true);
        Botan::PKCS11::Slot slot(module, Slots.at(0));
        Botan::PKCS11::Session session(slot, false);
        session.login(Botan::PKCS11::UserType::User, Pin);
        auto pub_keys =
            Botan::PKCS11::Object::search<Botan::PKCS11::PKCS11_RSA_PublicKey>(session, "KEEPASSXC_PUB_KEY");
        if (pub_keys.empty()) {
            gen_keys(session);
        }
        auto priv_keys = Botan::PKCS11::Object::search<Botan::PKCS11::PKCS11_RSA_PrivateKey>(session, "KEEPASSXC_PRIV_KEY");
        Botan::AutoSeeded_RNG rng;
        Botan::PK_Signer signer(priv_keys.at(0), rng, "EMSA_PKCS1(SHA-512)", Botan::IEEE_1363);
        auto res = signer.sign_message(plaintext, rng);
        session.logoff();
        for (auto symb : res) {
            m_key.push_back(static_cast<char>(symb));
        }
    }
    catch (std::exception& exception) {
        std::cout << exception.what() << std::endl;
    }
}


void PKCS11Key::gen_keys(Botan::PKCS11::Session& session)
{
    Botan::PKCS11::RSA_PrivateKeyGenerationProperties priv_generate_props;
    priv_generate_props.set_token(true);
    priv_generate_props.set_private(true);
    priv_generate_props.set_sign(true);
    priv_generate_props.set_decrypt(true);
    priv_generate_props.set_label("KEEPASSXC_PRIV_KEY");

    Botan::PKCS11::RSA_PublicKeyGenerationProperties pub_generate_props(2048UL);
    pub_generate_props.set_pub_exponent();
    pub_generate_props.set_label("KEEPASSXC_PUB_KEY");
    pub_generate_props.set_token(true);
    pub_generate_props.set_encrypt(true);
    pub_generate_props.set_verify(true);
    pub_generate_props.set_private(false);

    Botan::PKCS11::PKCS11_RSA_KeyPair rsa_keypair =
        Botan::PKCS11::generate_rsa_keypair(session, pub_generate_props, priv_generate_props);
}

QByteArray PKCS11Key::rawKey() const
{
    return QByteArray(m_key.data(), m_key.size());
}

void PKCS11Key::setRawKey(const QByteArray&)
{
    // nothing
}


QByteArray PKCS11Key::serialize() const
{
        QByteArray data;
        QDataStream stream(&data, QIODevice::WriteOnly);
        // don't know what add here
        stream << uuid().toRfc4122();
        return data;
}

void PKCS11Key::deserialize(const QByteArray& data)
{
        QDataStream stream(data);
        QByteArray uuidData;
        stream >> uuidData;
        if (uuid().toRfc4122() == uuidData) {
            ;
        }
}