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

sec_low_fr_sp_user = cc.generate_user_secret_key(
    msk, "Secrecy::Low && (Country::France || Country::Spain)", policy)

# Full encryption
plaintext = "My secret data"
plaintext_bytes = bytes(plaintext, 'utf-8')
additional_data = [0, 0, 0, 0, 0, 0, 0, 1];
authenticated_data = None;

ciphertext_bytes = cc.encrypt(policy, "Secrecy::High && Country::France", pk, plaintext_bytes, additional_data, authenticated_data)

# The medium secret marketing user can successfully decrypt a low security marketing message:
cleartext = cc.decrypt(sec_high_fr_sp_user, ciphertext_bytes, authenticated_data)

assert(str(bytes(cleartext), "utf-8") == plaintext)


# The low secret user cannot decrypt the message
try:
    cleartext = cc.decrypt(sec_low_fr_sp_user, ciphertext_bytes, authenticated_data)
except Exception as ex:
    print(f"As expected, user cannot decrypt this message: {ex}")

# Decomposed encryption
sym_key, enc_header = cc.encrypt_header(policy, "Secrecy::High && Country::France", pk, additional_data, authenticated_data)

crypted_data = cc.encrypt_symmetric_block(sym_key, plaintext_bytes, authenticated_data)

decrypted_sym_key, metadata = cc.decrypt_header(sec_high_fr_sp_user, enc_header, authenticated_data)

decrypted_data = cc.decrypt_symmetric_block(decrypted_sym_key, crypted_data, authenticated_data)

assert(str(bytes(decrypted_data), "utf-8") == plaintext)