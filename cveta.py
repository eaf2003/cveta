import time
import urllib2
#import urlparse
import sys
import re
import subprocess
import json
from bs4 import BeautifulSoup
#from collections import OrderedDict
import apt
cache = apt.Cache()

linDist = r'Ubuntu 16.04 LTS (Xenial Xerus)'
pkgColname = r'Package'
cveColname = r'CVE' 


print "CVEs for :" + linDist
#list pkg via cmd
#cmd = subprocess.Popen('dpkg -l | grep libc', shell=True, stdout=subprocess.PIPE)
#for line in cmd.stdout:
#    if "glibc" in line:
#        print line

##### GET RAW HTML        
tocrawl = set(["https://people.canonical.com/~ubuntu-security/cve/main.html"])  #MAIN REPO      
tocrawl2 = set(["https://people.canonical.com/~ubuntu-security/cve/universe.html"]) #UNIVERSE REPO
tocrawl3 = set(["https://people.canonical.com/~ubuntu-security/cve/partner.html"])

#tocrawl = set(["https://people.canonical.com/~ubuntu-security/cve/pkg/vim.html"])
#crawled = set([])
#keywordregex = re.compile('<meta\sname=["\']keywords["\']\scontent=["\'](.*?)["\']\s/>')
#linkregex = re.compile('<a\s*href=[\'|"](.*?)[\'"].*?>')



try:
    crawling = tocrawl.pop()
    print crawling
    response = urllib2.urlopen(crawling)
    msg = response.read()
    crawling2 = tocrawl2.pop()
    print crawling2
    response = urllib2.urlopen(crawling2)
    msg2 = response.read()

except KeyError:
    raise StopIteration
    response = urllib2.urlopen(crawling)
    msg = response.read()
    dato = msg[1:10]
    print dato
    for line2 in msg:
        print line2
    
s = msg
s2 = msg2
### GET TABLE
soup = BeautifulSoup(s,"lxml")
table = soup.find("table")#, attrs={"class":"details"})

soup2 = BeautifulSoup(s2,"lxml")
table2 = soup.find("table")

# The first tr contains the field names.
# get_text toma el text dentro de los tags tr
headings = [th.get_text() for th in table.find("tr").find_all("th")]
#this returns a list of 1 row with the array [cve, pkg ,ver1, ver1, ver3, ....]

#headingsno = 0
#headingsno = headingsno++ for th in table.find("tr").find_all("th")
#print headingsno

########	GET COL NUMBER PER EACH COLUM NAME OF INTEREST
#GET HEADER DISTRO COLUMN NUMBER, uso table 1 porque las demas serian iguales, si no crear uno de estos x cada table
distroCol = 0
for th in table.find("tr").find_all("th"): #iterate row 
	for valueth in th: #iterate thcol and get value
	#	print valueth #	deb
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
############ GET COLS NUMBER END



#distroStatusarr = []
#for row in table.find_all("tr")[1:]:
#	distrocolsel = 0
#	for td in row.find_all("td"): #itrate each td to count util distrocol
#		distrocolsel = distrocolsel +1
#		if distroColMatch == distrocolsel: #found the td that belong to that distro
#			distroStatusarr.append(td.get_text()) #hago array de distrostatus
			

#cve array
#cvecolsel = 0
#cveColmatch = 0 #primera cel no lo busco
#cveNamearr = []
#for row in table.find_all("tr")[1:]:
#	cvecolsel = 0
#	for td in row.find_all("td"): #itrate each td to count util distrocol
#		if cveColmatch == cvecolsel: #found the td that belong to that distro
#			cveNamearr.append(td.get_text()) #hago array de distrostatus
#		cvecolsel = cvecolsel +1	



##OLD TB REMOVE
datasets = []
for row in table.find_all("tr")[1:]:
    dataset = zip(headings, (td.get_text() for td in row.find_all("td")))
    datasets.append(dataset)


#jsondata = []

#print json.dumps(dict(datasets))

#print headings
#print datasets

##
##for dataset in datasets:
##   for field in dataset:
##        print "{0:<16}: {1}".format(field[0], field[1])

print "create list from data from internet,filtered by linux distro"
datasetA = []
#process table main
for row in table.find_all("tr")[1:]: #el 1: omite la 1er linea que contiene headings, iterate rows
	cells = row.find_all("td") #iterate tds in each row
#	print cells # DEBUG
#	time.sleep(3) #DEBUG
	#if cells[pkcolmatch] = VARnombrepackete:
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
	tableName2 = r'unverse'
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
def GetCVEWarning( Ipkgname ):
	global pkgNotfoundtotal
	global pkgFoundtotal
	global pkgFoundcvetotal
	datasetlocA = []
	global dataPkgnotfound
	pkgFound = 0
	global dataPkgfound
	global dataPkgwithcve
		###for row in table.find_all("tr")[1:]: #el 1: omite la 1er linea que contiene headings, iterate rows
		###cells = row.find_all("td") #iterate tds in each row
	for tuplaA in datasetA: #el 1 omite la 1er linea que contiene headings, iterate rows
		#cells = row.find_all("td") #iterate tds in each row

	#	print cells # DEBUG
	#	time.sleep(3) #DEBUG
		#if cells[pkcolmatch] = VARnombrepackete:
	#	print cells[distroColMatch].get_text() #DEBUG
	#	time.sleep(3) #DEBUG
		statusA = tuplaA[2] #get text from td that belong to distroStatus
		cvenoA = tuplaA[1] #cells[cveColMatch].get_text() #get text from td that belong to CVEno
		pkNameA = tuplaA[0] # cells[pkgnameColMatch].get_text()
		tableNameA = tuplaA[3]
		#	print pkName + " " + status #DEBUG
	#	time.sleep(3) #DEBUG
#		if pkName == Ipkgname and ( status != 'DNE' or status != r'not-affected*' or status != r'released*' )  :
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
				print "{0}: {1} :{2} : {3}".format(datalocA[0], datalocA[1], datalocA[2], datalocA[3])
	#print values
#	for tupla in datasetA:		
#			print "{0}: {1} :{2}".format(tupla[0], tupla[1], tupla[2])
	if pkgFound == 0 :
		if Ipkgname not in dataPkgnotfound: #count pkgs notfound
			dataPkgnotfound.append(Ipkgname)
	return




print "compare with local pkgs"


#LIST ALL PKGS INSTALLED
output = set()
for pkg in cache:
	if pkg.is_installed:
#		print pkg.name
#		print pkg.versions[0].source_name #usar este en vez de name
#		time.sleep(3)
#		GetCVEWarning(pkg.versions[0].source_name)
#		GetCVEWarning(pkg.name)
		output.add(pkg.versions[0].source_name)
#print output

#print output
for pkgsource in sorted(output): #ordered alpha
	#print pkgsource
	#time.sleep(1)
	GetCVEWarning(pkgsource)

print "---REPORT---"
print  str(pkgFoundcvetotal)  + "\t :Pkgs. with OPEN CVEs" 
print  str(pkgFoundtotal) + "\t :Pkgs. in Ubuntu tracker"	
print  str(len(dataPkgnotfound)) + "\t :Pkgs with not CVE or not installed from ubuntu repo"
print  str(len(output)) + "\t :Total Pkgs Installed on this system"

#1	print datasets2

#for dataset2 in datasets2:
#	for field in dataset2:
#		#print "{0:<16}: {1}".format(field[0], field[1])
#		print "{0}: {1}".format(field[0], field[1])
#		print field[1]


##for field in dataset2:
		#print "{0:<16}: {1}".format(field[0], field[1])
##		print "{0}: {1}".format(field[0], field[1])
#		print field[1]


########


