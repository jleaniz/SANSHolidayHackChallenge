import base64

'''
Convert Base64 encoded pdf attachment to a binary file.
'''

with open("base64_attachment", "r") as f:
	b64 = f.read()
	f.close()

with open("secret.pdf", "wb") as f:
	f.write(base64.b64decode(b64))
	f.close()

