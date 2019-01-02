import xml.etree.ElementTree as ET

tree = ET.parse('events.xml')
root = tree.getroot()
success = {}
fail = {}
user2ip = {}
tixreq = {}

for child in root:
	eid = child.getchildren()[0].getchildren()[1].text
	try:
		if eid == '4624':
			user = child.getchildren()[1].getchildren()[5].text
			ip = child.getchildren()[1].getchildren()[18].text
			temp_list = [ip]
			if user not in success:
				success[user] = 1
			else:
				success[user] += 1
			if user not in user2ip:	
				user2ip[user] = temp_list
			else:
				temp_list = user2ip[user]
				if ip not in temp_list:
					temp_list.append(ip)
					user2ip[user] = temp_list
		elif eid == '4625':
			user = child.getchildren()[1].getchildren()[5].text
			ip = child.getchildren()[1].getchildren()[18].text
			temp_list = [ip]
			if user not in fail:
				fail[user] = 1
			else:
				fail[user] += 1
		elif eid == '4769' or eid == '4768':
			user = child.getchildren()[1].getchildren()[0].text
			if user not in tixreq:
				tixreq[user] = 1
			else:
				tixreq[user] += 1
	except:
		print "error processing event. skipping..."

print sorted(success.items())
print sorted(fail.items())
print sorted(user2ip.items())
print sorted(tixreq.items())
