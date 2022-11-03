import json
from cosmian_cover_crypt import Attribute,Policy,PolicyAxis,CoverCrypt


country_axis = PolicyAxis("Country",["France", "UK", "Spain", "Germany"], False)
secrecy_axis = PolicyAxis("Secrecy",["Low", "Medium", "High"], True)

policy = Policy()
policy.add_axis(country_axis)
policy.add_axis(secrecy_axis)
print(policy.to_string())

attributes = policy.attributes()
assert(len(attributes) == 7)

cc = CoverCrypt()

msk, pk = cc.generate_master_keys(policy)

sec_high_fr_sp_user = cc.generate_user_secret_key(
    msk, "Secrecy::High && (Country::France || Country::Spain)", policy)

# Encryption
plaintext = "My secret data"
plaintext_bytes = bytes(plaintext, 'utf-8')
additional_data = [0, 0, 0, 0, 0, 0, 0, 1];
authenticated_data = None;

enc_header, cypher_bytes = cc.encrypt(policy, "Secrecy::High && Country::France", pk , plaintext_bytes, additional_data, authenticated_data)

# The medium secret marketing user can successfully decrypt a low security marketing message:
cleartext = cc.decrypt(sec_high_fr_sp_user, enc_header, cypher_bytes, authenticated_data)

assert(str(bytes(cleartext), "utf-8") == plaintext)