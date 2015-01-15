from lxml import html
import requests
from datetime import datetime
import csv
import re
import config

class Scraper(object):
	def __init__(self, numReports, start, end, escapeString):
		page = requests.get(str(numReports).join(self.url))
		self.tree = html.fromstring(page.text)
		self.startDate = (datetime.strptime(start, '%Y%m%d') - datetime(1970,1,1)).total_seconds()
		self.endDate = (datetime.strptime(end, '%Y%m%d') - datetime(1970,1,1)).total_seconds()
		self.filterUni = re.compile(escapeString)

	def getReportUrl(self):
		reports = self.tree.xpath(self.reportsXpath)
		for report in reports:
			self.getTimestamp(report)
			if self.timestamp > self.startDate and self.timestamp < self.endDate:
				yield report.xpath(self.reportLinkPath)[0]


	def writeCSV(self, filename):
		with open(filename, 'wb') as out:
			csv_out = csv.writer(out)
			for row in self.getReport():
				csv_out.writerow(row)

	def getReport(self):
		for report in self.getReportUrl():
			reportTree = html.fromstring(requests.get(report).text)
			content = reportTree.xpath(self.contentPath)[0]

			date = datetime.fromtimestamp(self.timestamp).strftime('%m/%d/%Y') # string

			title = self.getTitle(reportTree, content) # string

			name = self.getName(content) # string

			products = self.getProducts(content) # string

			cves = self.getCVEs(content) # list of strings
			amount = "A single vulnerability has been reported in" if \
					len(cves) <= 1 else "Multiple vulnerabilities have been reported in"
			cves = ", ".join(cves)
			if cves == '':
				cves = 'N/A'

			link = self.getLink(content) # string

			vulns = 'fix me'

			row = [date, title, name, products, cves, amount, vulns, link]
			row = self.extra(row)

			row = [''.join(self.filterUni.split(field)).encode('utf8') for field in row]

			print row[1]
			yield row

class CiscoScraper(Scraper):
	def __init__(self, numReports, start, end, escapeString):
		self.url = ['http://tools.cisco.com/security/center/publicationListing.x?method=getPsirtSearchData&searchDocType=CiscoSecurityNotice&sortOrder=d&sortType=lastPub&searchType=Basic&keyWord=&selectedCriteria=E&dateRange=All&publicationId=&firstPublishedStartDate=&firstPublishedEndDate=&lastPublishedStartDate=&lastPublishedEndDate=&afectedProduct=&affectedProductName=&cves=&ciscoBugId=&cvssBaseScore=&accessVectorField=A&accessComplexityField=A&authenticationField=A&confidentialityImpactField=A&integrityImpact=A&availabilityImpact=A&exploitabilityField=A&remediationLevelField=A&reportConfidenceField=A&pageStart=11&pageEnd=20&currentPage=1&pageSize=','&pageNo=2#~CiscoSecurityNotice#~CiscoSecurityNotice#~CiscoSecurityNotice']
		super(CiscoScraper, self).__init__(numReports, start, end, escapeString)
		self.reportsXpath = '//*[@id="info-CiscoSecurityNotice"]/table[@id="pubtypeinfo"]/tr[@class="apps-table-data"]'
		self.reportLinkPath = 'td/a/@href'
		self.contentPath = '//div[@id="framework-content-main"]'

	def getTimestamp(self, report):
		self.timestamp = (datetime.strptime(report.xpath('td[@class="cen"][2]/text()')[0].strip(), '%Y %B %d') -
				datetime(1970,1,1)).total_seconds()

	def getTitle(self, reportTree, content):
		return reportTree.xpath('//*[@id="framework-content-titles"]/h2/text()')[0].strip()

	def getName(self, content):
		return content.xpath('//div[@id="framework-content-main"]/h2/following-sibling::text()[1]')[0].strip()

	def getProducts(self, content):
		products = content.xpath('table/tr/following-sibling::*/td/text()')
		for line in reversed(xrange(len(products))):
			products[line] = products[line].strip()
			if products[line] == '' or re.match('[^a-zA-Z\d\s:]', products[line]) != None:
				del products[line]
		if len(products) > 0:
			# line breaks within a cell in excel
			products = '="{0}"'.format('" & CHAR(10) & "'.join(products).strip().encode('utf-8'))
		else: # something went wrong
			products = ''
		return products

	def getCVEs(self, content):
		return content.xpath('strong[1]/following-sibling::text()[1]')

	def getLink(self, content):
		return content.xpath('//div[@id="framework-content-main"]/a/text()')[0]

	def extra(self, row): # nothing else to do
		return row

class IBMScraper(Scraper):
	def __init__(self, numReports, start, end, escapeString):
		self.url = ['https://www-304.ibm.com/connections/blogs/PSIRT/?sortby=0&maxresults=','&page=0&lang=en_us']
		super(IBMScraper, self).__init__(numReports, start, end, escapeString)
		self.reportsXpath = '//*[@id="entries"]/table/tbody/tr[not(@style)]/td'
		self.reportLinkPath = 'h4/a/@href'
		self.contentPath = '/*/*/*/*/*/*[@id="entries"]/table/tbody/tr/td'

	def getTimestamp(self, report):
		self.timestamp = int(''.join(ele for ele in report.xpath('div[@class="lotusMeta"]/script/text()')[0] if ele.isdigit()))/1000

	def getTitle(self, reportTree, content):
		return content.xpath('h4/text()')[0].strip()

	def getName(self, content):
		return content.xpath('div[@class="entryContentContainer"]/p/text()')[0].strip()

	def getProducts(self, content):
		products = content.xpath('div[@class="entryContentContainer"]/div/p/text()')
		if products == [] or products[0].strip().encode('utf-8') == '':
			products = content.xpath('div[@class="entryContentContainer"]/div/table/tbody/tr/td/text()')
		if products == []:
			products = content.xpath('div[@class="entryContentContainer"]/div/ul/li/text()')
		if products == []:
			products = content.xpath('div[@class="entryContentContainer"]/p[2]/span/text()')
		if products == []:
			products = content.xpath('div[@class="entryContentContainer"]/p[2]/text()[1]')
		for line in reversed(xrange(len(products))):
			products[line] = products[line].strip()
			if products[line] == '':
				del products[line]
		if len(products) > 0: #it looks like a list:
			# supposedly how you do line breaks within a cell in excel
			products = '="{0}"'.format('" & CHAR(10) & "'.join(products).strip().encode('utf-8'))
		else: #something went wrong
			products = ''
		return products

	def getCVEs(self, content):
		return content.xpath('div[@class="entryContentContainer"]/p/u/a/b/text()')

	def getLink(self, content):
		return content.xpath('div[@class="entryContentContainer"]/p/u/a/text()')[0].strip()

	def extra(self, row):
		if ".wss?uid=" in row[7]: 
			details = html.fromstring(requests.get(row[7]).text)
			# i can actually get the name pretty reliably from here
			name = details.xpath('//*[@id="ibm-content-sidebar"]/div[4]/div/text()[3]')[0].strip()
			if name == '':
				name = details.xpath('//*[@id="ibm-content-sidebar"]/div[4]/div/a/text()')[0].strip()
			row[2] = name
		return row

if config.runCisco:
	cisco = CiscoScraper(config.ciscoResults, config.ciscoStart, config.ciscoEnd, config.escapeString)
	cisco.writeCSV('CiscoOutput.csv')

if config.runIBM:
	ibm = IBMScraper(config.ibmResults, config.ibmStart, config.ibmEnd, config.escapeString)
	ibm.writeCSV('IBMOutput.csv')
