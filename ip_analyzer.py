#!/usr/bin/python
#-------------------------------
# IP Address Geolocator
# Script written by Dushyanth Chowdary
#-------------------------------

#importing required libraries
import sys
import time
import sqlite3
import os
try:
	import argparse
	from urlparse import urlparse
	import whois
	import dns.resolver
	import requests
	import ipapi
	import simplekml
except ImportError:
	print "Missing a few required libraries - Please install before executing"
	sys.exit(0)


def fingerprint(addr):
	try : 
		r = requests.get(addr)
		return r.headers
	except requests.exceptions.InvalidSchema:
		print 'Misssing Schema in url - Please change url to format http://...'
		return None
	except requests.exceptions.ConnectionError:
		print 'No response from Server'
		return None
	except KeyboardInterrupt:
		sys.exit(1)

def find_location(ipa):
	location = []
	for addr in ipa:
		try:
			loca = ipapi.location(addr)
			location.append(loca)
		except Exception, e:
			print "Unable to GeoLocate IP Address - {0}".format(e)
	return location

if __name__ == "__main__":
	#configure argparse
	parser = argparse.ArgumentParser(description='Analyze URLs.')
	parser.add_argument('url', metavar='url', type=str, nargs='+', help='an url to analyze')
	parser.add_argument("-r", "--report", dest='r', action='store_true', help="Generates a report")
	parser.add_argument("-f", "--file", dest='f', action='store_true', help="Accept URLs from a file")
	parser.add_argument("-d", "--database", dest='d', action='store_true', help="Create a database")
	parser.add_argument("-k", "--kml", dest='k', action='store_true', help="Generate a KML file to view IP Geolocation in Google Earth")
	args = parser.parse_args()
	
	if (args.f):					# if -f flag is set, then read URLs from a file 
		arg_url = []
		for f in args.url:
			with open(f) as file:
				arg_url = file.read().split()
	else:
		arg_url = args.url

	try:
		os.remove("geoip.db")
	except:{}

	#sqlite3 database configuration
	if args.d:
		conn = sqlite3.connect('geoip.db')
		conn.text_factory = str
		c = conn.cursor()
		c.execute('''CREATE TABLE geoip (URL TEXT, Whois TEXT, DNS TEXT, Server_Fingerprint TEXT, GeoLocate_IP TEXT);''')
		conn.commit()

	#initialize counters and variables
	final_data = {}
	counter = 0
	succ_counter = 0
	fail_counter = 0
	part_counter = 0

	for arg in arg_url:
		
		counter += 1
		ar = urlparse(arg)

		print ar.netloc
		final_data[ar.netloc] = {}
		# Get Whois Infomation
		try:
			print 'Getting Whois Data...'
			wis = whois.whois(ar.netloc)			
			final_data[ar.netloc]['whois'] = wis
			if wis is not None:
				wistest = True
			else:
				wistest = False
		except Exception, e:
		 	print 'Unable to retrieve WhoIs information'
		 	final_data[ar.netloc]['whois'] = None
		 	wistest = False

		#Resolve DNS
		try:
			print 'Getting DNS info...'
			answer = dns.resolver.query(ar.netloc)	 
			final_data[ar.netloc]['dns'] = answer
			if answer is not None:
				dnstest = True
			else:
				dnstest = False
		except Exception, e:
			print 'Unable to resolve DNS. Error -> {0}'.format(e)
			final_data[ar.netloc]['dns'] = None
			dnstest = False
		
		#Function to fingerprint server using response headers
		print 'Attempting to fingerprint server...'
		sfprint = fingerprint('{0}://{1}/'.format(ar.scheme,ar.netloc))
		if sfprint is not None:
			final_data[ar.netloc]['fprint'] = sfprint
			sftest = True
		else:
			final_data[ar.netloc]['fprint'] = None
			sftest = False
		
		#Finding location of IP address
		print 'Attempting to GeoLocate IP Address...'
		location = find_location(answer)
		if location is not None:
			final_data[ar.netloc]['location'] = location
			geotest = True
		else:
			final_data[ar.netloc]['location'] = None
			geotest = False
		
		#update counters
		if wistest and sftest and geotest and dnstest:
			succ_counter += 1
		elif wistest or sftest or geotest or dnstest:
			part_counter += 1
		else:
			fail_counter += 1

		time.sleep(3)

	if args.k:
		kml = simplekml.Kml()

	# Print output to screen
	print '\n\nSUMMARY : '
	print '--------------------------------------------------'
	print 'Total URLs Analyzed - {0}'.format(counter)
	print 'Sucessfully analyzed Url - {0}'.format(succ_counter)
	print 'Partially analyzed Url - {0}'.format(part_counter)
	print 'Failed to analyze Url - {0}'.format(fail_counter)

	if args.r:
		report = open('url_analysis_report.txt','w')
		report.write('--------------------------------------------------\nReport Summary\n')
		report.write('Total URLs Analyzed - {0}\n'.format(counter))
		report.write('Sucessfully analyzed Url - {0}\n'.format(succ_counter))
		report.write('Partially analyzed Url - {0}\n'.format(part_counter))
		report.write('Failed to analyze Url - {0}\n'.format(fail_counter))
		report.write('--------------------------------------------------\n\n')


	for urls in final_data.keys():
		print '\n\n--------------------------------------------------'
		print '{0} : '.format(urls)
		print '--------------------------------------------------'
		if args.r:
			report.write('\n\n--------------------------------------------------\n{0} :\n--------------------------------------------------'.format(urls))
			report.write('\nWHOIS INFORMATION : \n')
		print '\nWHOIS INFORMATION : \n'
		if final_data[urls]['whois'] is not None:
			for w in final_data[urls]['whois'].keys():
				print ('{0} : {1}'.format(w,final_data[urls]['whois'][w]))
				if args.r:
					report.write('{0} : {1}\n'.format(w,final_data[urls]['whois'][w]))
		else:
			print 'Error Getting WhoIs Information'

		if args.r:
			report.write('\nDNS INFORMATION : \n')
		print '\nDNS INFORMATION : \n'
		ipno = 0
		if final_data[urls]['dns'] is not None:
			for ans in final_data[urls]['dns']:
				print '____________________\n IP {0} Location - \n____________________'.format(ipno)
				n = dns.reversename.from_address(str(ans))
				print 'resolved name'
				print n
				print 'address'
				print ans
				if args.r:
					report.write('____________________\n IP {0} Location - \n____________________\n'.format(ipno))
					report.write('Resolved Name : {0}\n'.format(n))
					report.write('Address : {0}\n'.format(ans))
				ipno += 1
		else:
			print 'Error Getting DNS Information'

		if args.r:
			report.write('\nSERVER FINGERPRINTING : \n')
		print '\nSERVER FINGERPRINTING : \n'
		if final_data[urls]['fprint'] is not None:
			for sf in final_data[urls]['fprint'].keys():
				print ('{0} : {1}'.format(sf,final_data[urls]['fprint'][sf]))
				if args.r:
					report.write('{0} : {1}\n'.format(sf,final_data[urls]['fprint'][sf]))
		else:
			print 'Error Fingerprinting Server'
		if args.r:
			report.write('\nIP GEOLOCATION : \n')
		print '\nIP GEOLOCATION : \n'
		adno = 0
		if final_data[urls]['location'] is not None:
			for loc in final_data[urls]['location']:
				print '____________________\n IP {0} Location - \n____________________'.format(adno)
				if args.r:
					report.write('____________________\n IP {0} Location - \n____________________\n'.format(adno))
				for l in loc.keys():
					try:
						print ('{0} : {1}'.format(l,loc[l]))
					except UnicodeEncodeError:
						pass
					if args.r:
						try:
							report.write('{0} : {1}\n'.format(l,loc[l]))
						except UnicodeEncodeError:
							pass

				if args.k:
					kml.newpoint(name=urls, description=loc['ip'], coords=[(loc['longitude'],loc['latitude'])])
				adno+=1
		else:
			print 'Error Getting IP Geolocation'
		print '--------------------------------------------------'
		
		if args.r:
			report.write('--------------------------------------------------')
		if args.d:
			c.execute("INSERT INTO geoip (URL, Whois, DNS, Server_Fingerprint, GeoLocate_IP) VALUES (?,?,?,?,?)",(urls,str(final_data[urls]['whois']),','.join(str(v) for v in final_data[urls]['dns']),str(final_data[urls]['fprint']),','.join(str(lo) for lo in final_data[urls]['location'])))
			conn.commit()

	if args.k:				# if KML flag was set generate the final kml file
		kml.save("ipgeolocate.kml")
	if args.d:
		conn.close()	
