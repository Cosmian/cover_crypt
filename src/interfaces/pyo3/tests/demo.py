import cover_crypt
import json


# Data to be written
policy_json = {"last_attribute_value": 10, "max_attribute_value": 100, "store": {"Security Level": [["Protected", "Low Secret", "Medium Secret", "High Secret", "Top Secret"], True], "Department": [["R&D", "HR", "MKG", "FIN"], False]}, "attribute_to_int": {
    "Security Level::Low Secret": [2], "Department::MKG": [8], "Security Level::Medium Secret": [3], "Security Level::Top Secret": [5], "Security Level::Protected": [1], "Department::FIN": [10, 9], "Department::HR": [7], "Department::R&D": [6], "Security Level::High Secret": [4]}}

policy = bytes(json.dumps(policy_json), 'utf-8')

master_keys = cover_crypt.generate_master_keys(policy)

top_secret_mkg_fin_user = cover_crypt.generate_user_private_key(
    master_keys[0], "Security Level::Top Secret && (Department::MKG || Department::FIN)", policy)

medium_secret_mkg_user = cover_crypt.generate_user_private_key(
    master_keys[0], "Security Level::Medium Secret && Department::MKG", policy)


# Encryption
metadata_json = {"uid": [0, 0, 0, 0, 0, 0, 0, 1]}
metadata = bytes(json.dumps(metadata_json), 'utf-8')
plaintext = "My secret data"

# Encrypt with different ABE policies
low_secret_mkg_data = cover_crypt.encrypt(metadata, policy, bytes(json.dumps(
    ['Security Level::Low Secret', 'Department::MKG']), 'utf8'), master_keys[1], bytes(plaintext, 'utf-8'))
top_secret_mkg_data = cover_crypt.encrypt(metadata, policy, bytes(json.dumps(
    ['Security Level::Top Secret', ' Department::MKG']), 'utf8'), master_keys[1], bytes(plaintext, 'utf-8'))
low_secret_fin_data = cover_crypt.encrypt(metadata, policy, bytes(json.dumps(
    ['Security Level::Low Secret', 'Department::FIN']), 'utf8'), master_keys[1], bytes(plaintext, 'utf-8'))

# The medium secret marketing user can successfully decrypt a low security marketing message:
cleartext = cover_crypt.decrypt(medium_secret_mkg_user, low_secret_mkg_data)
assert(str(bytes(cleartext), "utf-8") == plaintext)

# .. however it can neither decrypt a marketing message with higher security:
try:
    cleartext = cover_crypt.decrypt(
        medium_secret_mkg_user, top_secret_mkg_data)
except Exception as ex:
    print(f"As expected, user cannot decrypt this message: {ex}")

try:
    cleartext = cover_crypt.decrypt(
        medium_secret_mkg_user, low_secret_fin_data)
except Exception as ex:
    print(f"As expected, user cannot decrypt this message: {ex}")

# The "top secret-marketing-financial" user can decrypt messages from the marketing department OR the financial department that have a security level of Top Secret or below
# As expected, the top secret marketing financial user can successfully decrypt all messages
cleartext = cover_crypt.decrypt(top_secret_mkg_fin_user, low_secret_mkg_data)
assert(str(bytes(cleartext), "utf-8") == plaintext)

cleartext = cover_crypt.decrypt(top_secret_mkg_fin_user, top_secret_mkg_data)
assert(str(bytes(cleartext), "utf-8") == plaintext)

cleartext = cover_crypt.decrypt(top_secret_mkg_fin_user, low_secret_fin_data)
assert(str(bytes(cleartext), "utf-8") == plaintext)
