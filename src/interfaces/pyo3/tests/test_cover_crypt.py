import unittest
from cosmian_cover_crypt import Attribute, Policy, PolicyAxis, CoverCrypt

class TestPolicy(unittest.TestCase):

    def test_attribute(self) -> None:
        att = Attribute("Country","France")
        self.assertEqual(att.to_string(), 'Country::France')
        self.assertEqual(Attribute.from_string('Country::France').to_string(), 'Country::France')


    def test_policy_creation_rotation(self) -> None:
        country_axis = PolicyAxis("Country",["France", "UK", "Spain", "Germany"], False)
        self.assertEqual(country_axis.to_string(), 'Country: ["France", "UK", "Spain", "Germany"], hierarchical: false')
        secrecy_axis = PolicyAxis("Secrecy",["Low", "Medium", "High"], True)
        self.assertEqual(secrecy_axis.to_string(), 'Secrecy: ["Low", "Medium", "High"], hierarchical: true')
        policy = Policy()
        policy.add_axis(country_axis)
        policy.add_axis(secrecy_axis)
        # test attributes
        attributes = policy.attributes()
        self.assertEqual(len(attributes),4+3)
        # rotate
        france_attribute=Attribute("Country","France")
        france_value = policy.attribute_current_value(france_attribute)
        self.assertEqual(france_value,1)
        policy.rotate(france_attribute)
        new_france_value = policy.attribute_current_value(france_attribute)
        self.assertEqual(new_france_value,8)
        self.assertEqual(policy.attribute_values(france_attribute),[8,1])


class TestEncryption(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        country_axis = PolicyAxis("Country",["France", "UK", "Spain", "Germany"], False)
        secrecy_axis = PolicyAxis("Secrecy",["Low", "Medium", "High"], True)
        cls.policy = Policy()
        cls.policy.add_axis(country_axis)
        cls.policy.add_axis(secrecy_axis)

        cls.cc = CoverCrypt()

    
    def test_full_encryption_decryption(self) -> None:

        msk, pk = TestEncryption.cc.generate_master_keys(TestEncryption.policy)

        plaintext = "My secret data"
        plaintext_bytes = bytes(plaintext, 'utf-8')
        additional_data = [0, 0, 0, 0, 0, 0, 0, 1];
        authenticated_data = None;

        ciphertext_bytes = TestEncryption.cc.encrypt(TestEncryption.policy, "Secrecy::High && Country::France",
                                                    pk, plaintext_bytes, additional_data, authenticated_data)

        sec_high_fr_sp_user = TestEncryption.cc.generate_user_secret_key(msk,
            "Secrecy::High && (Country::France || Country::Spain)", TestEncryption.policy)
        
        # Successful decryption
        cleartext = TestEncryption.cc.decrypt(sec_high_fr_sp_user, ciphertext_bytes, authenticated_data)
        self.assertEqual(str(bytes(cleartext), "utf-8"), plaintext)

        # Wrong key
        sec_low_fr_sp_user = TestEncryption.cc.generate_user_secret_key(msk,
            "Secrecy::Low && (Country::France || Country::Spain)", TestEncryption.policy)

        with self.assertRaises(Exception):
            cleartext = TestEncryption.cc.decrypt(sec_low_fr_sp_user, ciphertext_bytes, authenticated_data)


        # /!\ policy rotation can impact the other tests
        france_attribute = Attribute("Country","France")
        # new_policy = deepcopy(TestEncryption.policy)
        TestEncryption.policy.rotate(france_attribute)

        new_msk, new_pk = TestEncryption.cc.generate_master_keys(TestEncryption.policy)
        new_ciphertext = TestEncryption.cc.encrypt(TestEncryption.policy,
            "Secrecy::High && Country::Spain", new_pk, plaintext_bytes,
            additional_data, authenticated_data)

        # user cannot decrypt the new message until its key is refreshed
        with self.assertRaises(Exception):
            cleartext = TestEncryption.cc.decrypt(sec_high_fr_sp_user, new_ciphertext,
                                                  authenticated_data)

        new_sec_high_fr_sp_user = TestEncryption.cc.generate_user_secret_key(new_msk,
            "Secrecy::High && (Country::France || Country::Spain)", TestEncryption.policy)
        
        # new user key cannot decrypt the old message
        with self.assertRaises(Exception):
            cleartext = TestEncryption.cc.decrypt(new_sec_high_fr_sp_user, ciphertext_bytes,
                                                  authenticated_data)

        cleartext = TestEncryption.cc.decrypt(new_sec_high_fr_sp_user, new_ciphertext, authenticated_data)
        self.assertEqual(str(bytes(cleartext), "utf-8"), plaintext)


    def test_decomposed_encryption_decryption(self) -> None:

        msk, pk = TestEncryption.cc.generate_master_keys(TestEncryption.policy)

        plaintext = "My secret data"
        plaintext_bytes = bytes(plaintext, 'utf-8')
        additional_data = [0, 0, 0, 0, 0, 0, 0, 1];
        authenticated_data = None;

        sym_key, enc_header = TestEncryption.cc.encrypt_header(TestEncryption.policy,
            "Secrecy::Medium && Country::UK", pk, additional_data, authenticated_data)

        crypted_data = TestEncryption.cc.encrypt_symmetric_block(sym_key, plaintext_bytes, authenticated_data)

        sec_med_uk_user = TestEncryption.cc.generate_user_secret_key(msk,
            "Secrecy::Medium && Country::UK", TestEncryption.policy)

        decrypted_sym_key, metadata = TestEncryption.cc.decrypt_header(sec_med_uk_user, enc_header, authenticated_data)

        self.assertEqual(metadata, additional_data)

        decrypted_data = TestEncryption.cc.decrypt_symmetric_block(decrypted_sym_key, crypted_data, authenticated_data)

        self.assertEqual(str(bytes(decrypted_data), "utf-8"), plaintext)


if __name__ == '__main__':
    unittest.main()