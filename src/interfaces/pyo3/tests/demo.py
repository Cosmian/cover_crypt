import json
import cosmian_cover_crypt


# Declare 2 CoverCrypt policy axis:
policy_axis_json = [
    {
        "name": "Security Level",
        "attributes": [
            "Protected",
            "Low Secret",
            "Medium Secret",
            "High Secret",
            "Top Secret"
        ],
        "hierarchical": True
    },
    {
        "name": "Department",
        "attributes": [
            "R&D",
            "HR",
            "MKG",
            "FIN"
        ],
        "hierarchical": False
    }
]

policy_axis = bytes(json.dumps(policy_axis_json), 'utf-8')

policy = cosmian_cover_crypt.generate_policy(
    policy_axis_bytes=policy_axis, max_attribute_value=100)

master_keys = cosmian_cover_crypt.generate_master_keys(policy)

top_secret_mkg_fin_user = cosmian_cover_crypt.generate_user_secret_key(
    master_keys[0], "Security Level::Top Secret && (Department::MKG || Department::FIN)", policy)

medium_secret_mkg_user = cosmian_cover_crypt.generate_user_secret_key(
    master_keys[0], "Security Level::Medium Secret && Department::MKG", policy)


# Encryption
plaintext = "My secret data"
plaintext_bytes = bytes(plaintext, 'utf-8')
additional_data = [0, 0, 0, 0, 0, 0, 0, 1];
anthentication_data = [];

# Encrypt with different ABE policies
low_secret_mkg_data = cosmian_cover_crypt.encrypt(policy, "Security Level::Low Secret && Department::MKG",
                                                  master_keys[1],
                                                  plaintext_bytes,
                                                  additional_data,
                                                  authentication_data)
top_secret_mkg_data = cosmian_cover_crypt.encrypt(policy, "Security Level::Top Secret && Department::MKG",
                                          master_keys[1], plaintext_bytes,
                                          additional_data, authentication_data)
low_secret_fin_data = cosmian_cover_crypt.encrypt(policy, "Security Level::Low Secret && Department::FIN",
                                          master_keys[1], plaintext_bytes,
                                          additional_data, authentication_data)

# The medium secret marketing user can successfully decrypt a low security marketing message:
cleartext = cosmian_cover_crypt.decrypt(medium_secret_mkg_user, low_secret_mkg_data,
                                authentication_data)
assert(str(bytes(cleartext), "utf-8") == plaintext)

# .. however it can neither decrypt a marketing message with higher security:
try:
    cleartext = cosmian_cover_crypt.decrypt(
        medium_secret_mkg_user, top_secret_mkg_data, authentication_data)
except Exception as ex:
    print(f"As expected, user cannot decrypt this message: {ex}")

try:
    cleartext = cosmian_cover_crypt.decrypt(
        medium_secret_mkg_user, low_secret_fin_data, authentication_data)
except Exception as ex:
    print(f"As expected, user cannot decrypt this message: {ex}")

# The "top secret-marketing-financial" user can decrypt messages from the marketing
# department OR the financial department that have a security level of Top Secret or below

# As expected, the top secret marketing financial user can successfully decrypt all messages
cleartext = cosmian_cover_crypt.decrypt(top_secret_mkg_fin_user, low_secret_mkg_data,
                                authentication_data)
assert(str(bytes(cleartext), "utf-8") == plaintext)

cleartext = cosmian_cover_crypt.decrypt(top_secret_mkg_fin_user, top_secret_mkg_data,
                                authentication_data)
assert(str(bytes(cleartext), "utf-8") == plaintext)

cleartext = cosmian_cover_crypt.decrypt(top_secret_mkg_fin_user, low_secret_fin_data,
                                authentication_data)
assert(str(bytes(cleartext), "utf-8") == plaintext)

# Rotation of Policy attributes
# At anytime, Policy attributes can be rotated.
# When that happens future encryption of data for a "rotated" attribute cannot
# be decrypted with user decryption keys which are not "refreshed" for that
# attribute. Let us rotate the Security Level Low Secret
new_policy = cosmian_cover_crypt.rotate_attributes(bytes(json.dumps(
    ['Security Level::Low Secret']), 'utf8'), policy)
# # Printing the policy before and after the rotation of the attribute.
# print("Before the rotation of attribute Security Level::Low Secret")
# print(json.loads(str(bytes(policy), "utf-8")))
# print("After attributes rotation")
# print(json.loads(str(bytes(new_policy), "utf-8")))

# Master keys MUST be refreshed
master_keys = cosmian_cover_crypt.generate_master_keys(new_policy)
new_low_secret_mkg_data = cosmian_cover_crypt.encrypt(new_policy, "Security Level::Low Secret && Department::MKG",
                                              master_keys[1], plaintext_bytes,
                                              additional_data, authentication_data)

# The medium secret user cannot decrypt the new message until its key is refreshed
try:
    cleartext = cosmian_cover_crypt.decrypt(
        medium_secret_mkg_user, new_low_secret_mkg_data, authentication_data)
except Exception as ex:
    print(f"As expected, user cannot decrypt this message: {ex}")

# Refresh medium secret key
new_medium_secret_mkg_user = cosmian_cover_crypt.generate_user_secret_key(
    master_keys[0], "Security Level::Medium Secret && Department::MKG", new_policy)

# New messages can now be decrypted
cleartext = cosmian_cover_crypt.decrypt(
    new_medium_secret_mkg_user, new_low_secret_mkg_data, authentication_data)
assert(str(bytes(cleartext), "utf-8") == plaintext)
