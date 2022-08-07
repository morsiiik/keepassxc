#ifndef KEEPASSXC_PKCS11KEY_H
#define KEEPASSXC_PKCS11KEY_H

#include "Key.h"
#include <botan/p11.h>
#include <botan/p11_slot.h>
#include <botan/p11_module.h>
#include <botan/p11_rsa.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <iostream>
#include <unistd.h>


class PKCS11Key : public Key
{
public:
    PKCS11Key();
    static QUuid UUID;

    ~PKCS11Key() override = default;

    void sign_data(const std::string& file_path, Botan::PKCS11::secure_string Pin);
    void gen_keys(Botan::PKCS11::Session& session);

    QByteArray rawKey() const override;
    void setRawKey(const QByteArray&) override;
    QByteArray serialize() const override;
    void deserialize(const QByteArray& data) override;

private:
    size_t slotID = 0;

    // DATA FOR SIGN
    const Botan::secure_vector<uint8_t> plaintext = { 0x00, 0x01, 0x02, 0x03 };
    // signed data
    Botan::secure_vector<char> m_key;
    bool m_isInitialized = false;


};

#endif // KEEPASSXC_PKCS11KEY_H
