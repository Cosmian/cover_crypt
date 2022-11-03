import json
from cosmian_cover_crypt import Attribute,Policy,PolicyAxis,CoverCrypt


att = Attribute("Country","France")
print(att.to_string())

country_axis = PolicyAxis("Country",["France", "UK", "Spain", "Germany"], False)
print(country_axis.to_string())
secrecy_axis = PolicyAxis("Secrecy",["Low", "Medium", "High"], True)

policy = Policy()
policy.add_axis(country_axis)
policy.add_axis(secrecy_axis)
print(policy.to_string())

attributes = policy.attributes()
print(len(attributes))

cc = CoverCrypt()

msk, pk = cc.generate_master_keys(policy)

print(msk)
