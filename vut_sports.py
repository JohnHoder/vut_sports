#!/usr/bin/env
# -*- coding: utf-8 -*-
import re
import cookielib
import urllib
import urllib2
import logging
import sys

try:
	import requests
	from bs4 import BeautifulSoup

except ImportError:
		print "\nPlease make sure you have BeautifulSoup and requests modules installed!\n"
		exit()

DEBUG = False

if DEBUG == True:
	try:
		import http.client as http_client
	except ImportError:
		# Python 2
		import httplib as http_client

	http_client.HTTPConnection.debuglevel = 1

	# You must initialize logging, otherwise you'll not see debug output.
	logging.basicConfig()
	logging.getLogger().setLevel(logging.DEBUG)
	requests_log = logging.getLogger("requests.packages.urllib3")
	requests_log.setLevel(logging.DEBUG)
	requests_log.propagate = True


class VUTSportRegister(object):

	def __init__(self, username, password, sport_name, day_of_occurence, hour_from, hour_till):
		super(VUTSportRegister, self).__init__()
		self.username = username
		self.password = password

		self.sport_name = sport_name
		self.day_of_occurence = day_of_occurence
		self.hour_from = hour_from
		self.hour_till = hour_till

		self.session = requests.Session()

	def getTextOnly(self, soupedHtml):
		# kill all script and style elements
		for script in soupedHtml(["script", "style"]):
			script.extract()    # rip it out
		# get text
		text = soupedHtml.get_text(separator=' ')
		# break into lines and remove leading and trailing space on each
		lines = (line.strip() for line in text.splitlines())
		# break multi-headlines into a line each
		chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
		# drop blank lines
		text = '\n'.join(chunk for chunk in chunks if chunk)

		return (text)

	def login(self):
		url_login1 = 'https://www.vutbr.cz/login/'

		header1={
				"Host" : "www.vutbr.cz",
				"User-Agent" : "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0",
				"Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Language" : "en-US,en;q=0.5",
				"Accept-Encoding" : "gzip, deflate, br",
				"Referer" : "https://www.vutbr.cz/",
				"Cookie" : "nosec_sess=7KHeaY61v1; __utma=257111820.1390290382.1472933322.1474064831.1474484625.27; __utmz=257111820.1472933322.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none); vut_ack=z0JYvEJwjvuFzgAFlFHbr2HUb2Kn6Q; portal_is_logged_in=0; _ga=GA1.2.1390290382.1472933322; __atuvc=1%7C37; PHPSESSID=shreck6-185926-1474486334-20392-02c709784722a2a196417bbc99c871c49c39cbf2; hash_uzivatele=c419a53c6f071cc030704734a2a49639; SimpleSAMLSessionID=bb0ac5d00a784a60189881717a9a9aac; rotate=3; __utmc=257111820; __utmb=257111820.33.9.1474486337583; __utmt=1",
				"Upgrade-Insecure-Requests" : "1",
				"Connection" : "close",
				"Content-Type" : "application/x-www-form-urlencoded",
				}

		res = self.session.get(url_login1, headers=header1, allow_redirects=True)
		soup = BeautifulSoup(res.text, "lxml")
		sentTime = soup.find("input", {"name": "sentTime"})['value']
		svfdkey = soup.find("input", {"name": "sv[fdkey]"})['value']

		#print sentTime + " " + svfdkey

		url_login2 = 'https://www.vutbr.cz/login/in'

		header2={
				"Host" : "www.vutbr.cz",
				"User-Agent" : "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0",
				"Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Language" : "en-US,en;q=0.5",
				"Accept-Encoding" : "gzip, deflate, br",
				"Referer" : "https://www.vutbr.cz/login?fdkey=" + svfdkey + "&armsgt=WxWlEQ2XSu",
				"Cookie" : "nosec_sess=7KHeaY61v1; __utma=257111820.1390290382.1472933322.1474064831.1474484625.27; __utmz=257111820.1472933322.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none); vut_ack=z0JYvEJwjvuFzgAFlFHbr2HUb2Kn6Q; portal_is_logged_in=0; _ga=GA1.2.1390290382.1472933322; __atuvc=1%7C37; PHPSESSID=shreck6-185926-1474486334-20392-02c709784722a2a196417bbc99c871c49c39cbf2; hash_uzivatele=c419a53c6f071cc030704734a2a49639; SimpleSAMLSessionID=bb0ac5d00a784a60189881717a9a9aac; rotate=3; __utmc=257111820; __utmb=257111820.33.9.1474486337583; __utmt=1",
				"Upgrade-Insecure-Requests" : "1",
				"Connection" : "close",
				"Content-Type" : "application/x-www-form-urlencoded",
				}

		get_params= {}

		payload = {"special_p4_form" : "1",
					"login_form" : "1",
					"sentTime" : sentTime,
					"sv%5Bfdkey%5D" : svfdkey,
					"LDAPlogin" : self.username,
					"LDAPpasswd" : self.password,
					"login" : "" 
					}

		res = self.session.post(url_login2, params=get_params, data=payload, headers=header2, allow_redirects=False)
		print "######################################################"
		print "######################################################"

		redir_loc = res.headers['Location']
		print res.status_code, res.reason, " => ", redir_loc
		print "PHPSESSID:", res.cookies['PHPSESSID']

		#main = self.session.get(redir_loc, allow_redirects=True)
		#print main.headers
		#print main.text

		print "######################################################"
		print "######################################################"

	def registerSport(self):

		url_sporty = "https://www.vutbr.cz/studis/student.phtml?sn=zapis_sportu"
		payload2 = {}

		header = {
				"Host" : "www.vutbr.cz",
				"User-Agent" : "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0",
				"Accept" : "*/*",
				"Accept-Language" : "en-US,en;q=0.5",
				"Accept-Encoding" : "gzip, deflate, br",
				"Referer" : "https://www.vutbr.cz/studis/student.phtml?sn=aktuality_predmet",
				"Content-Type" : "application/x-www-form-urlencoded; charset=UTF-8"
				}

		sporty = self.session.get(url_sporty, data=payload2, headers=header, allow_redirects=True)
		sporty.encoding = 'utf-8'

		soup = BeautifulSoup(sporty.text, "lxml")
		soup.prettify()
		#print soup

		sport_url = ""

		for elem in soup(text=re.compile(r'(.*)' + self.sport_name + '(.*)')):
			#print elem.parent
			sport_url = "https://www.vutbr.cz/studis/student.phtml" + elem.parent['href']
			sport_id = re.findall(r'\d+', elem.parent['href'])[0]
			print "Your sport has been found: " + sport_id

		sport_inside = self.session.get(sport_url, data=payload2, headers=header, allow_redirects=True)
		sport_inside.encoding = 'utf-8'

		soup = BeautifulSoup(sport_inside.text, "lxml")
		soup.prettify()

		s_key = soup.find("input", {"name": "s_key"})['value']
		#print s_key
		s_tkey = soup.find("input", {"name": "s_tkey"})['value']
		#print s_tkey

		#print soup

		my_sport_box = ""

		counter = 1
		for elem in soup(text=re.compile(r"" + hour_from + "(.*)" + hour_till)):
			if counter == self.day_of_occurence:
				my_sport_box = elem.parent
			counter = counter + 1

		#print my_sport_box
		lesson_id = my_sport_box.parent.find("input", {"name": "vyucovani_id", "type" : "radio"})['value']
		print "ID of the lesson: " + lesson_id

		#################################
		### REGISTER THE SPORT LESSON ###
		#################################

		url_register = "https://www.vutbr.cz/studis/student.phtml"

		payload = {"sn" : "zapis_sportu_act",
					"s_key" : s_key,
					"s_tkey" : s_tkey,
					"vyucovani_id" : lesson_id,
					"formular_zapis_sportu_submit" : "Potvrdit+z%C3%A1pis+term%C3%ADnu+sportu",
					"action" : "zapsat_sport",
					"apid" : sport_id
					}

		header = {
				"Host" : "www.vutbr.cz",
				"User-Agent" : "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0",
				"Accept" : "*/*",
				"Accept-Language" : "en-US,en;q=0.5",
				"Accept-Encoding" : "gzip, deflate, br",
				"X-Requested-With" : "XMLHttpRequest",
				"Referer" : "https://www.vutbr.cz/studis/student.phtml?sn=zapis_sportu&apid=" + sport_id,
				"Content-Type" : "application/x-www-form-urlencoded; charset=UTF-8",
				"Upgrade-Insecure-Requests" : "1",
				"Connection" : "close"
				}

		sporty = self.session.post(url_register, data=payload, headers=header, allow_redirects=True)
		sporty.encoding = 'utf-8'

		soup = BeautifulSoup(sporty.text, "lxml")
		#print soup.prettify()

		try:
			print self.getTextOnly(soup.find("ul", {"class": "vutMsg error col-w-m"}))
		except:
			pass
		try:
			print self.getTextOnly(soup.find("ul", {"class": "vutMsg ok col-w-m"}))
		except:
			pass


		return sporty.status_code


if __name__ == "__main__":
	username = "username"
	password = "password"

	sport_name = "Bootcamp"

	day_of_occurence = 1

	hour_from = "7:15"
	hour_till = "8:15"

	sa = VUTSportRegister(username, password, sport_name, day_of_occurence, hour_from, hour_till)
	sa.login()
	sa.registerSport()
