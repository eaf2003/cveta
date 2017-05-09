#cveta cve task automation for ubuntu cve tracker
#run: "python cveta.py" or "python3 cveta.py"
#
#requires:
#python3 --> python --version to check or use python3 if have both
#urllib for py3 -->pip3 install urllib
#bautifulsoup for py 3 -> sudo pip3 install --upgrade beautifulsoup4
#
import time
import urllib.request, urllib.error, urllib.parse
#import urlparse
import sys
import re
import subprocess
#import json
from bs4 import BeautifulSoup
#from collections import OrderedDict
import apt
cache = apt.Cache()

#####vars########### to include as command line options
linDist = r'Ubuntu 16.04 LTS (Xenial Xerus)'
pkgColname = r'Package'
cveColname = r'CVE' 
#####/vars###########

print(("CVEs for :" + linDist))
#list pkg via cmd
#cmd = subprocess.Popen('dpkg -l | grep libc', shell=True, stdout=subprocess.PIPE)
#for line in cmd.stdout:
#    if "glibc" in line:
#        print line

##### GET RAW HTML #########################################
tocrawl = set(["https://people.canonical.com/~ubuntu-security/cve/main.html"])  #MAIN REPO      
tocrawl2 = set(["https://people.canonical.com/~ubuntu-security/cve/universe.html"]) #UNIVERSE REPO
tocrawl3 = set(["https://people.canonical.com/~ubuntu-security/cve/partner.html"])

#tocrawl = set(["https://people.canonical.com/~ubuntu-security/cve/pkg/vim.html"])
#crawled = set([])
#keywordregex = re.compile('<meta\sname=["\']keywords["\']\scontent=["\'](.*?)["\']\s/>')
#linkregex = re.compile('<a\s*href=[\'|"](.*?)[\'"].*?>')



try:
    crawling = tocrawl.pop()
    print(crawling)
    response = urllib.request.urlopen(crawling)
    msg = response.read()
    
    crawling2 = tocrawl2.pop()
    print(crawling2)
    response2 = urllib.request.urlopen(crawling2)
    msg2 = response2.read()

except KeyError:
    raise StopIteration
    response = urllib.request.urlopen(crawling)
    msg = response.read()
    dato = msg[1:10]
    print(dato)
    for line2 in msg:
        print(line2)
    
s = msg
s2 = msg2
### GET TABLE
soup = BeautifulSoup(s,"lxml")
table = soup.find("table")#, attrs={"class":"details"})

soup2 = BeautifulSoup(s2,"lxml")
table2 = soup2.find("table")

# The first tr contains the field names.
# get_text toma el text dentro de los tags tr
headings = [th.get_text() for th in table.find("tr").find_all("th")]
#this returns a list of 1 row with the array [cve, pkg ,ver1, ver1, ver3, ....]

#headingsno = 0
#headingsno = headingsno++ for th in table.find("tr").find_all("th")
#print headingsno

########	GET COL NUMBER PER EACH COLUMN NAME OF INTEREST####
#GET HEADER DISTRO COLUMN NUMBER, assume all tables will have same headers, uso la table 1 porque las demas serian iguales, si no crear uno de estos x cada table
distroCol = 0
for th in table.find("tr").find_all("th"): #iterate left to rigth first row as contains th 
	for valueth in th: #iterate thcol and get value
		print(valueth) #	deb
		if linDist == valueth:
	#if r'Ubuntu 16.04 LTS (Xenial Xerus)' == valueth:	
			distroColMatch = distroCol
	#		print distroColMatch #deb
		distroCol = distroCol+1	#pruebo la prox col
		
#GET HEADER CVE# COLUMN NUMBER
cveCol = 0
for th in table.find("tr").find_all("th"): #iterate row
	for valueth in th: #iterate thcol and get value
		if cveColname == valueth:
			cveColMatch = cveCol
		cveCol = cveCol+1
		
#GET HEADER PKGName COLUMN NUMBER
pkgColnumber = 0
for th in table.find("tr").find_all("th"): #iterate row
	for valueth in th: #iterate thcol and get value
		if pkgColname == valueth:
			pkgnameColMatch = pkgColnumber
		pkgColnumber = pkgColnumber+1		
############ GET COLS NUMBER END################################


##OLD TB REMOVE
datasets = []
for row in table.find_all("tr")[1:]:
    dataset = list(zip(headings, (td.get_text() for td in row.find_all("td"))))
    datasets.append(dataset)


#jsondata = []

#print json.dumps(dict(datasets))

#print headings
#print datasets

##
##for dataset in datasets:
##   for field in dataset:
##        print "{0:<16}: {1}".format(field[0], field[1])

print("create list from data from internet,filtered by linux distro")
datasetA = []
#process table main
for row in table.find_all("tr")[1:]: #el 1: omite la 1er linea que contiene headings, iterate rows
	cells = row.find_all("td") #iterate tds in each row
#	print cells # DEBUG
#	time.sleep(3) #DEBUG
#	print cells[distroColMatch].get_text() #DEBUG
#	time.sleep(3) #DEBUG
	status = cells[distroColMatch].get_text() #get text from td that belong to distroStatus
	cveno = cells[cveColMatch].get_text() #get text from td that belong to CVEno
	pkName = cells[pkgnameColMatch].get_text()
	tableName = r'main'
#	print pkName + " " + status #DEBUG
#	time.sleep(3) #DEBUG
	dataA = (pkName, cveno, status, tableName) #create tuple each time
#	print dataA
	datasetA.append(dataA) #append tuple to array, so i create a list
#process table2 universe		
for row2 in table2.find_all("tr")[1:]:
	cells2 = row2.find_all("td")
	status2 = cells2[distroColMatch].get_text() #get text from td that belong to distroStatus
	cveno2 = cells2[cveColMatch].get_text() #get text from td that belong to CVEno
	pkName2 = cells2[pkgnameColMatch].get_text()
	tableName2 = r'universe'
	dataA = (pkName2, cveno2, status2, tableName2) #create tuple each time
#	print dataA
	datasetA.append(dataA) #append tuple to array, so i create a list
	
	
#print datasetA #debug

pkgNotfoundtotal = 0
pkgFoundtotal = 0
pkgFoundcvetotal = 0
dataPkgwithcve = []
dataPkgnotfound = []
dataPkgfound = []
def GetCVEWarning( Ipkgname ):#compares pkcsource name on sys vs pkgname on tables
	global pkgNotfoundtotal
	global pkgFoundtotal
	global pkgFoundcvetotal
	datasetlocA = []
	global dataPkgnotfound
	pkgFound = 0
	global dataPkgfound
	global dataPkgwithcve
		###for row in table.find_all("tr")[1:]: #el 1: omite la 1er linea que contiene headings, iterate rows
	for tuplaA in datasetA: #el 1 omite la 1er linea que contiene headings, iterate rows
		statusA = tuplaA[2] #get text from td that belong to distroStatus
		cvenoA = tuplaA[1] #cells[cveColMatch].get_text() #get text from td that belong to CVEno
		pkNameA = tuplaA[0] # cells[pkgnameColMatch].get_text()
		tableNameA = tuplaA[3] #source table universe main etc...
		if pkNameA == Ipkgname:
			pkgFound = 1
			if pkNameA not in dataPkgfound: #count pkgs processed
				dataPkgfound.append(pkNameA)
				pkgFoundtotal = pkgFoundtotal + 1
			if pkNameA == Ipkgname and statusA != 'DNE' and statusA != r'not-affected*' and statusA != r'released*' :
				if pkNameA not in dataPkgwithcve: #count pkgs with cves
					dataPkgwithcve.append(pkNameA)
					pkgFoundcvetotal = pkgFoundcvetotal + 1
				datalocA = (pkNameA, cvenoA, statusA, tableNameA) #create tuple each time
		#		print dataA
				datasetlocA.append(datalocA) #append tuple to array, so i create a list	
				print("{0}: {1} :{2} : {3}".format(datalocA[0], datalocA[1], datalocA[2], datalocA[3]))
	if pkgFound == 0 :
		if Ipkgname not in dataPkgnotfound: #count pkgs notfound
			dataPkgnotfound.append(Ipkgname)	
	return




print("compare with local pkgs")


#create scrPkglist unique, contains all pkgs installed on this system- not repeated names
srcPkglist = set()
for pkg in cache:
	if pkg.is_installed:
#		print(pkg.name)
#		print(pkg.versions[0].source_name #usar este en vez de name)
#		time.sleep(3)
		srcPkglist.add(pkg.versions[0].source_name)

for pkgsource in sorted(srcPkglist): #ordered alpha a-z
	GetCVEWarning(pkgsource) #process each pkg

print("---REPORT---")
print(str(pkgFoundcvetotal)  + "\t :Pkgs. with OPEN CVEs on this system") 
print(str(pkgFoundtotal) + "\t :Pkgs. for this system in Ubuntu tracker")	
print(str(len(dataPkgnotfound)) + "\t :Pkgs with not CVE or not installed from ubuntu repo")
print(str(len(srcPkglist)) + "\t :Total Pkgs Installed on this system")

#1	print datasets2

#for dataset2 in datasets2:
#	for field in dataset2:
#		#print "{0:<16}: {1}".format(field[0], field[1])
#		print "{0}: {1}".format(field[0], field[1])
#		print field[1]


########


