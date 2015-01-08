###
# Make sure the Run variable is set to true if you want its scraper to run.
# Go to the urls for each site and find how many results there are since your start date
# by going back pages until you see the last one you want.
# Set results to that number.
# Set start to the start date in format yyyymmdd.
# Set end to the end date in the same format.
# The outputs will be files named IBMOutput.csv, CiscoOutput.csv, etc.
# They will be in the working directory when the script is run.
###


# Cisco
# url: http://tools.cisco.com/security/center/publicationListing.x?method=getPsirtSearchData&searchDocType=CiscoSecurityNotice&sortOrder=d&sortType=lastPub&searchType=Basic&keyWord=&selectedCriteria=E&dateRange=All&publicationId=&firstPublishedStartDate=&firstPublishedEndDate=&lastPublishedStartDate=&lastPublishedEndDate=&afectedProduct=&affectedProductName=&cves=&ciscoBugId=&cvssBaseScore=&accessVectorField=A&accessComplexityField=A&authenticationField=A&confidentialityImpactField=A&integrityImpact=A&availabilityImpact=A&exploitabilityField=A&remediationLevelField=A&reportConfidenceField=A&pageStart=11&pageEnd=20&currentPage=1&pageSize=15&pageNo=2#~CiscoSecurityNotice#~CiscoSecurityNotice#~CiscoSecurityNotice
runCisco 		= True
ciscoResults	= 20
ciscoStart 		= '20141217'
ciscoEnd 		= '20150107'

# IBM
# url: https://www-304.ibm.com/connections/blogs/PSIRT/?sortby=0&maxresults=15&page=0&lang=en_us
runIBM 			= True
ibmResults 		= 13
ibmStart 		= '20150101'
ibmEnd 			= '20150106'


# If you encounter an error when running that says something like:
# UnicodeDecodeError: 'ascii' codec can't decode byte 0x9e in position 15: ordinal not in range(128)
# add the byte to the escape string by adding a pipe | followed by the byte in the same format as already in the string.
escapeString = u'\xa0|\xae|\xc2|\xe2|\x80|\x93|\x98|\x99|\xb7|\x84|\xa2|\xc3|\x82|\xac|\x9c|\x9e'