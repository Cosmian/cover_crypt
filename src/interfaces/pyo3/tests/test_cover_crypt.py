import unittest
from cosmian_cover_crypt import Attribute, Policy, PolicyAxis, CoverCrypt
from copy import deepcopy

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

        cls.msk, cls.pk = cls.cc.generate_master_keys(cls.policy)

        cls.plaintext = "My secret data"
        cls.plaintext_bytes = bytes(cls.plaintext, 'utf-8')
        additional_data = [0, 0, 0, 0, 0, 0, 0, 1];
        cls.authenticated_data = None;

        cls.ciphertext_bytes = cls.cc.encrypt(cls.policy, "Secrecy::High && Country::France", cls.pk,
                                              cls.plaintext_bytes, additional_data, cls.authenticated_data)

    
    def test_successful_decryption(self) -> None:
        sec_high_fr_sp_user = TestEncryption.cc.generate_user_secret_key(TestEncryption.msk,
            "Secrecy::High && (Country::France || Country::Spain)", TestEncryption.policy)
        
        cleartext = TestEncryption.cc.decrypt(sec_high_fr_sp_user, TestEncryption.ciphertext_bytes,
                                                TestEncryption.authenticated_data)
        self.assertEqual(str(bytes(cleartext), "utf-8"), TestEncryption.plaintext)


    def test_wrong_key_policy(self) -> None:
        sec_low_fr_sp_user = TestEncryption.cc.generate_user_secret_key(TestEncryption.msk,
            "Secrecy::Low && (Country::France || Country::Spain)", TestEncryption.policy)

        with self.assertRaises(Exception):
            cleartext = TestEncryption.cc.decrypt(sec_low_fr_sp_user, TestEncryption.ciphertext_bytes,
                                                TestEncryption.authenticated_data)


if __name__ == '__main__':
    unittest.main()