#!/usr/bin/env python3
# run: "python cveta.py" or "python3 cveta.py"
#
# requires:
# python3 --> python --version to check or use python3 if have both
# urllib for py3 -->pip3 install urllib
# beautifulsoup for py 3 -> sudo pip3 install --upgrade beautifulsoup4
#
# TO DO :analize pkg: option to enter a pckg name, output name, source, ver, cves. json file: create a json from the table and process it
# add input args: select distro, verbose, brief, output to file option.
# eaf may 2017

# import time
# import urllib.request, urllib.error, urllib.parse
# import sys
# import re
# import subprocess
from bs4 import BeautifulSoup
import apt
import argparse
import requests

# DISTRO NAMAS AS SEEN ON UBUNTU CVE TABLE WEBPAGE
DISTS = dict(
    xenial='Ubuntu 16.04 LTS (Xenial Xerus)',
    yakkety='Ubuntu 16.10 LTS (Yakkety Yak)',
    last='Ubuntu 17.10 (Artful Aardvark)',
)

# args input NOT FULLY IMPLEMENTED YET
parseArgs1 = argparse.ArgumentParser()
# parseArgs1.add_argument('-h', '--help', help='no-help')
parseArgs1.add_argument('-b', '--brief', action='store_true', help='Shows only a brief')
parseArgs1.add_argument('-v', '--verbose', action='count', default=0, help='Super Verbose')
parseArgs1.add_argument('-D', '--dist', choices=list(DISTS.keys()),
                        default='xenial')  # by def use 'Ubuntu 16.04 LTS (Xenial Xerus)'
args = parseArgs1.parse_args()
# print(args.brief)


# apt cache to get local packages
cache = apt.Cache()

# ####vars########### to include as command line options
linux_distro_name = DISTS[args.dist]  # r'Ubuntu 16.04 LTS (Xenial Xerus)'
# col names as seen on ubuntu cve webpage
pkg_table_col_name = r'Package'
cve_table_col_name = r'CVE'
# ####/vars###########

if not args.brief:
    print("cveta says: use '-b' option to show only a report")

print(("CVEs for :" + linux_distro_name))
#   list pkg via cmd
#   cmd = subprocess.Popen('dpkg -l | grep libc', shell=True, stdout=subprocess.PIPE)
#   for line in cmd.stdout:
#        if "glibc" in line:
#         print line

# #### GET RAW HTMLS #########################################
url_main = "https://people.canonical.com/~ubuntu-security/cve/main.html"
url_univ = "https://people.canonical.com/~ubuntu-security/cve/universe.html"  # UNIVERSE REPO
url_partner = "https://people.canonical.com/~ubuntu-security/cve/partner.html"
try:
    if not args.brief:
        print("Fetching data from:")
        print(url_main)
        print(url_univ)
        print(url_partner)

    response = requests.get(url_main)
    msg = response.content
    if response.status_code != 200:
        raise ValueError('bad url')

    response2 = requests.get(url_univ)
    msg2 = response2.content

    response3 = requests.get(url_partner)
    msg3 = response3.content
except KeyError:
     raise StopIteration
     print("error X")

# ##GET TABLES FROM HTMLS
soup = BeautifulSoup(msg, "html.parser")
table = soup.find("table")  # , attrs={"class":"details"})

soup2 = BeautifulSoup(msg2, "html.parser")
table2 = soup2.find("table")

soup3 = BeautifulSoup(msg3, "html.parser")
table3 = soup3.find("table")

# GET HEADING NAMES, NO NEEDED
# The first tr contains the field names.
# get_text toma el text dentro de los tags tr
# headings = [th.get_text() for th in table.find("tr").find_all("th")]
# this returns a list of 1 row with the array [cve, pkg ,ver1, ver1, ver3, ....]

# #######    GET COL NUMBER PER EACH COLUMN NAME OF INTEREST####
# FIND N GET HEADER DISTRO COLUMN NUMBER, assume all tables will have same headers, uso la table 1 porque las demas serian iguales, si no crear uno de estos x cada table
# as the tables could change by ubuntu cve tr. 'masters', i'd not consolidate its parsing in an unique func.
# better to treat those independently

linux_distro_col_idx = None
cve_col_idx = None
pkgname_col_idx = None
for i, th in enumerate(table.find("tr").find_all("th")):  # iterate left to rigth first row as contains th
    valueth = th.text
    if linux_distro_name == valueth:
        linux_distro_col_idx = i
    elif cve_table_col_name == valueth:
        cve_col_idx = i
    elif pkg_table_col_name == valueth:
        pkgname_col_idx = i

if linux_distro_col_idx is None or cve_col_idx is None or pkgname_col_idx is None:
    raise StopIteration

############ GET COLS NUMBER END################################

##OLD TB REMOVE
# datasets = []
# for row in table.find_all("tr")[1:]:
#   dataset = list(zip(headings, (td.get_text() for td in row.find_all("td"))))
#    datasets.append(dataset)

## MERGE ALL TABLES IN ONE DATASET WITH COLUMNS PKNAME,CVENUMBER,STATUS,REPOSITORYPROVIDERNAME
print("create list from data from internet,filtered by linux distro")
dt_all = []
# process table main
def merge_tables(table_soup, table_name):
    for row in table_soup.find_all("tr")[1:]:  # el 1: omite la 1er linea que contiene headings, iterate rows
        cells = row.find_all("td")  # iterate tds in each row
        #    print cells[distroColMatch].get_text() #DEBUG
        #    time.sleep(3) #DEBUG
        status = cells[linux_distro_col_idx].get_text()  # get text from td that belong to distroStatus
        cveno = cells[cve_col_idx].get_text()  # get text from td that belong to CVEno
        pkName = cells[pkgname_col_idx].get_text()
        dataA = (pkName, cveno, status, table_name)  # create tuple each time
        #    print dataA
        dt_all.append(dataA)  # append tuple to array, so i create a list

merge_tables(table, 'main')
merge_tables(table2, 'universe')
merge_tables(table3, 'partner')

# CREATE A DATASET(datasetCVEA) WITH LOCAL DETECTED VULNERABILITIES, WITH COLUMNS PKNAME,CVENUMBER,STATUS,REPOSITORYPROVIDERNAME
dt_pkg_with_cve = []
dt_pkg_not_found = []
dt_pkg_found = []
datasetCVEA = []
def get_cve_warning(Ipkgname):  # compares pkcsource name on sys vs pkgname on tables
    #   global dt_pkg_not_found
    pkgFound = 0
    for tuplaA in dt_all:  # el 1 omite la 1er linea que contiene headings, iterate rows
        statusA = tuplaA[2]  # get text from td that belong to distroStatus
        cvenoA = tuplaA[1]  # cells[cveColMatch].get_text() #get text from td that belong to CVEno
        pkNameA = tuplaA[0]  # cells[pkgnameColMatch].get_text()
        tableNameA = tuplaA[3]  # source table universe main etc...
        if pkNameA == Ipkgname:
            pkgFound = 1
            if pkNameA not in dt_pkg_found:  # count pkgs processed
                dt_pkg_found.append(pkNameA)
            if pkNameA == Ipkgname and statusA != 'DNE' and statusA != r'not-affected*' and statusA != r'not-affected' and statusA != r'released*' and statusA != r'released':
                if pkNameA not in dt_pkg_with_cve:  # count pkgs with cves
                    dt_pkg_with_cve.append(pkNameA)
                datalocA = (pkNameA, cvenoA, statusA, tableNameA)  # create tuple each time
                #        print dataA
                datasetCVEA.append(datalocA)  # append tuple to array, so i create a list
                if not args.brief:
                    print("{0:30}: {1:14} :{2:14} : {3:10}".format(datalocA[0], datalocA[1], datalocA[2], datalocA[3]))
    if pkgFound == 0:
        if Ipkgname not in dt_pkg_not_found:  # count pkgs notfound
            dt_pkg_not_found.append(Ipkgname)
    return

print("Comparing with local pkgs...")
# check by pkcsourne name , DISABLED
# create scrPkglist unique, contains all pkgs installed on this system- not repeated names
lst_pkg_source_name = set()
for pkg in cache:
    if pkg.is_installed:
        #       print(pkg.name)
        #       print(pkg.versions[0].source_name #usar este en vez de name)
        #        time.sleep(3)
        # lst_pkg_source_name.add(pkg.name)
        lst_pkg_source_name.add(pkg.versions[0].source_name)
# for pkgsource in sorted(lst_pkg_source_name): #ordered alpha a-z
#    GetCVEWarning(pkgsource) #process each pkg

# check by name
lst_pkg_name = set()
for pkg in cache:
    if pkg.is_installed:
        lst_pkg_name.add(pkg.name)
        # lst_pkg_source_name.add(pkg.versions[0].source_name)
for pkgname in sorted(lst_pkg_name):  # ordered alpha a-z
    get_cve_warning(pkgname)  # process each pkg

print("\n---REPORT---")
print(str(len(dt_pkg_with_cve)) + "\t :Pkgs. with OPEN CVEs on this system with " + str(len(datasetCVEA)) + " CVEs")
print(str(len(dt_pkg_found)) + "\t :Pkgs. for this system in Ubuntu CVE tracker")
print(str(len(dt_pkg_not_found)) + "\t :Pkgs. without CVEs or not installed from standards repos")
print(str(len(lst_pkg_name)) + "\t :Total Pkgs. Installed on this system, with (" + str(
    len(lst_pkg_source_name)) + ") sources")

if not args.brief:
    print(
        # '"DNE" means that the package does not exist within the lineage'+
        # '"ignored" means that energy is not being expended for determining whether the problem exists in the particular package within the lineage, because support has ended for one reason or another. See for instance the linux-lts-quantal package, in the Ubuntu 12.04 LTS lineage. Support for that particular package (a backported hardware enablement package) in that lineage is beyond end-of-life.'
        '\n"needs triage" means that the package within the lineage is still supported, but work is needed to determine if the reported problem actually exists.'
        # '"not affected" means that the underlying source code vulnerability exists in the particular package within the lineage, but triage determined that for some other reason the issue will not occur. See for instance "linux-mako" within Ubuntu 16.04 LTS.'
        '\n"needed" of course means that triage has determined that the package within the lineage is affected, but work to apply the fix to the particular package within the lineage is still needed.'
        '\n"pending" means that the work needed to apply the fix to the particular package within the lineage has been done, a version has been cut, and a release is in the works.'
        # '"released" means that the fix for the package within the lineage has been released"'
    )

    # if __name__ == '__main__':
    #   print('hi')