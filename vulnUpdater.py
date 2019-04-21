import xml.etree.ElementTree as ET
import os

# Downloads & loads vuln list into memory
os.system('wget https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-modified.xml.gz -P /root/')
os.system('gunzip /root/nvdcve-2.0-modified.xml')
tree = ET.parse('/root/nvdcve-2.0-modified.xml')
root = tree.getroot()

# Init vars
listing,installed_list = [],[]

# Gets list of installed apps
os.system('apt list --installed >> /root/test.txt')
installed_file = open("/root/test.txt", "r").read().split('\n')
os.system('rm /root/test.txt')

# Parses installed list into apps list
for x in xrange(0,len(installed_file)):
	if '/' in installed_file[x]:
		installed_list.append(installed_file[x].split('/')[0])

# Parses out xml file into application list & desc
for x in xrange(0,len(root)):
	text = ''
	try: text = root[x][1][0].text
	except: 
		try: text = root[x][2][0].text
		except: continue
	if text and (not '\n' in text) and ('cpe' in text):
		doc = text.split(':')[2]
		if not doc in listing: listing.append(doc)
		
# Checks installed list against xml parsed
common = list(set(listing).intersection(installed_list))

# Upgrade all packages that have vulnerabilities for their versions
os.system('apt upgrade '+' '.join(common)+' -y')
	
