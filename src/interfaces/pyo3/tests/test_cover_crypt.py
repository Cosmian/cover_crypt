import unittest
from cosmian_cover_crypt import Attribute, Policy, PolicyAxis, CoverCrypt, SymmetricKey


class TestPolicy(unittest.TestCase):
    def test_attribute(self) -> None:
        att = Attribute("Country", "France")
        self.assertEqual(att.to_string(), "Country::France")
        self.assertEqual(
            Attribute.from_string("Country::France").to_string(), "Country::France"
        )

    def test_policy_creation_rotation(self) -> None:
        country_axis = PolicyAxis(
            "Country", ["France", "UK", "Spain", "Germany"], False
        )
        self.assertEqual(
            country_axis.to_string(),
            'Country: ["France", "UK", "Spain", "Germany"], hierarchical: false',
        )
        secrecy_axis = PolicyAxis("Secrecy", ["Low", "Medium", "High"], True)
        self.assertEqual(
            secrecy_axis.to_string(),
            'Secrecy: ["Low", "Medium", "High"], hierarchical: true',
        )
        policy = Policy()
        policy.add_axis(country_axis)
        policy.add_axis(secrecy_axis)
        # test attributes
        attributes = policy.attributes()
        self.assertEqual(len(attributes), 4 + 3)
        # rotate
        france_attribute = Attribute("Country", "France")
        france_value = policy.attribute_current_value(france_attribute)
        self.assertEqual(france_value, 1)
        policy.rotate(france_attribute)
        new_france_value = policy.attribute_current_value(france_attribute)
        self.assertEqual(new_france_value, 8)
        self.assertEqual(policy.attribute_values(france_attribute), [8, 1])

    def test_policy_cloning_serialization(self):
        country_axis = PolicyAxis(
            "Country", ["France", "UK", "Spain", "Germany"], False
        )
        secrecy_axis = PolicyAxis("Secrecy", ["Low", "Medium", "High"], True)
        policy = Policy()
        policy.add_axis(country_axis)
        policy.add_axis(secrecy_axis)

        copy_policy = policy.clone()
        self.assertIsInstance(copy_policy, Policy)

        json_str = policy.to_json()
        self.assertEqual(json_str, copy_policy.to_json())

        deserialized_policy = Policy.from_json(json_str)
        self.assertIsInstance(deserialized_policy, Policy)

        with self.assertRaises(Exception):
            Policy.from_json("wrong data format")


class TestEncryption(unittest.TestCase):
    def setUp(self) -> None:
        country_axis = PolicyAxis(
            "Country", ["France", "UK", "Spain", "Germany"], False
        )
        secrecy_axis = PolicyAxis("Secrecy", ["Low", "Medium", "High"], True)
        self.policy = Policy()
        self.policy.add_axis(country_axis)
        self.policy.add_axis(secrecy_axis)

        self.cc = CoverCrypt()
        self.msk, self.pk = self.cc.generate_master_keys(self.policy)

        self.plaintext = b"My secret data"
        self.additional_data = [0, 0, 0, 0, 0, 0, 0, 1]
        self.authenticated_data = None

    def test_full_encryption_decryption(self) -> None:

        ciphertext = self.cc.encrypt(
            self.policy,
            "Secrecy::High && Country::France",
            self.pk,
            self.plaintext,
            self.additional_data,
            self.authenticated_data,
        )

        sec_high_fr_sp_user = self.cc.generate_user_secret_key(
            self.msk,
            "Secrecy::High && (Country::France || Country::Spain)",
            self.policy,
        )

        # Successful decryption
        cleartext = self.cc.decrypt(
            sec_high_fr_sp_user, ciphertext, self.authenticated_data
        )
        self.assertEqual(bytes(cleartext), self.plaintext)

        # Wrong key
        sec_low_fr_sp_user = self.cc.generate_user_secret_key(
            self.msk, "Secrecy::Low && (Country::France || Country::Spain)", self.policy
        )

        with self.assertRaises(Exception):
            cleartext = self.cc.decrypt(
                sec_low_fr_sp_user, ciphertext, self.authenticated_data
            )

    def test_policy_rotation(self) -> None:

        ciphertext = self.cc.encrypt(
            self.policy,
            "Secrecy::High && Country::France",
            self.pk,
            self.plaintext,
            self.additional_data,
            self.authenticated_data,
        )

        sec_high_fr_sp_user = self.cc.generate_user_secret_key(
            self.msk,
            "Secrecy::High && (Country::France || Country::Spain)",
            self.policy,
        )

        france_attribute = Attribute("Country", "France")
        # new_policy = deepcopy(self.policy)
        self.policy.rotate(france_attribute)

        self.cc.update_master_keys(self.policy, self.msk, self.pk)
        new_plaintext = b"My secret data 2"
        new_ciphertext = self.cc.encrypt(
            self.policy,
            "Secrecy::High && Country::France",
            self.pk,
            new_plaintext,
            self.additional_data,
            self.authenticated_data,
        )

        # user cannot decrypt the new message until its key is refreshed
        with self.assertRaises(Exception):
            cleartext = self.cc.decrypt(
                sec_high_fr_sp_user, new_ciphertext, self.authenticated_data
            )

        # new user can still decrypt old message with keep_old_accesses
        self.cc.refresh_user_secret_key(
            sec_high_fr_sp_user,
            "Secrecy::High && (Country::France || Country::Spain)",
            self.msk,
            self.policy,
            keep_old_accesses=True,
        )

        cleartext = self.cc.decrypt(
            sec_high_fr_sp_user, ciphertext, self.authenticated_data
        )
        self.assertEqual(bytes(cleartext), self.plaintext)

        # new user key can no longer decrypt the old message
        self.cc.refresh_user_secret_key(
            sec_high_fr_sp_user,
            "Secrecy::High && (Country::France || Country::Spain)",
            self.msk,
            self.policy,
            keep_old_accesses=False,
        )
        with self.assertRaises(Exception):
            cleartext = self.cc.decrypt(
                sec_high_fr_sp_user, ciphertext, self.authenticated_data
            )

        cleartext = self.cc.decrypt(
            sec_high_fr_sp_user, new_ciphertext, self.authenticated_data
        )
        self.assertEqual(bytes(cleartext), new_plaintext)

    def test_decomposed_encryption_decryption(self) -> None:

        sym_key, enc_header = self.cc.encrypt_header(
            self.policy,
            "Secrecy::Medium && Country::UK",
            self.pk,
            self.additional_data,
            self.authenticated_data,
        )
        self.assertIsInstance(sym_key, SymmetricKey)

        ciphertext = self.cc.encrypt_symmetric_block(
            sym_key, self.plaintext, self.authenticated_data
        )

        sec_med_uk_user = self.cc.generate_user_secret_key(
            self.msk, "Secrecy::Medium && Country::UK", self.policy
        )

        decrypted_sym_key, decrypted_metadata = self.cc.decrypt_header(
            sec_med_uk_user, enc_header, self.authenticated_data
        )
        self.assertEqual(decrypted_metadata, self.additional_data)

        decrypted_data = self.cc.decrypt_symmetric_block(
            decrypted_sym_key, ciphertext, self.authenticated_data
        )
        self.assertEqual(bytes(decrypted_data), self.plaintext)


if __name__ == "__main__":
    unittest.main()
