#!/usr/bin/python
#------------------------------------------------
# Python Program to extract pictures and PDF from disk images.
# Written by Dushyanth Chowdary
# 
#
# Information is stored in database extractor.db
# Report.txt contains the all infomation on extracted images and pdfs
#------------------------------------------------

#import required libraries
import sqlite3
import os

try:
	import pytsk3
except ImportError:
	print 'Pytsk3 module not installed. Run the following commands:'
	print 'git clone https://github.com/py4n6/pytsk.git'
	print 'cd pytsk'
	print 'apt-get install autotools-dev automake libtool'
	print 'python setup.py update'
	print 'python setup.py build'
	print 'python setup.py install'
	sys.exit(0)

try:
	import magic
except ImportError:
	print 'Magic module not installed. Run the following command:'
	print 'pip install python-magic'
	sys.exit(0)

try:
	import argparse
except ImportError:
	print 'ArgParse module not installed. Run the following command:'
	print 'pip install argparse'
	sys.exit(0)

#global variables
allowed = [ "image/gif",
			"image/jpeg",
			"image/png",
			"image/x-ms-bmp",
			"image/svg+xml",
			"application/pdf"]

images = []
pdf = []

#function to extract files recursively from the images
def recursive_extract(dirObject, parentPath, img, conn):

	c = conn.cursor()

	#recursively move through the image filesystem
	for begin in dirObject:
		if begin.info.name.name in [".", ".."]:
			continue

		try:					#try to grab the type if the file
			f_type = begin.info.meta.type
		except:
			print "Cannot retrieve type of",begin.info.name.name
			continue

		try:					#Traverse the filesystem
			filepath = '/{0}/{1}'.format('/'.join(parentPath),begin.info.name.name)
			outputPath ='./{0}/{1}/'.format("Recover_"+str(img),'/'.join(parentPath))

			if f_type == pytsk3.TSK_FS_META_TYPE_DIR:		#if directory traverse into it
				sub_directory = begin.as_directory()
				parentPath.append(begin.info.name.name)
				recursive_extract(sub_directory,parentPath,img, conn)
				parentPath.pop(-1)
				print "\n\nDirectory: {0}".format(filepath)

			elif f_type == pytsk3.TSK_FS_META_TYPE_REG and begin.info.meta.size != 0:	#if file and size > 1
				filedata = begin.read_random(0,begin.info.meta.size)

				if magic.from_buffer(filedata[:1024], mime=True) in allowed: 			#check if file is an image or pdf
					
					# store data of file in database
					c.execute("INSERT INTO recover VALUES (?,?,?,?,?,?,?)",(img,begin.info.meta.addr,magic.from_buffer(filedata[:1024], mime=True),begin.info.name.name,begin.info.meta.crtime,begin.info.meta.mtime,begin.info.meta.size))
					conn.commit()
					print "Extracting File : " + str(['/'.join(parentPath)+begin.info.name.name])
					
					#create new folder to extract the file
					if not os.path.exists(outputPath):
						os.makedirs(outputPath)

					#extract the file
					extractFile = open(outputPath+begin.info.name.name,'w')
					extractFile.write(filedata)
					extractFile.close

					#keep count on number of images extracted
					if magic.from_buffer(filedata[:1024], mime=True) == "image/gif" or magic.from_buffer(filedata[:1024], mime=True) =="image/jpeg" or magic.from_buffer(filedata[:1024], mime=True) =="image/png" or magic.from_buffer(filedata[:1024], mime=True) =="image/x-ms-bmp" or magic.from_buffer(filedata[:1024], mime=True) =="image/svg+xml":
						images.append(begin.info.name.name)
					#keep count on number of pdf extracted
					elif magic.from_buffer(filedata[:1024], mime=True) == "application/pdf":
						pdf.append(begin.info.name.name)

			#if file but file size is 0 
			elif f_type == pytsk3.TSK_FS_META_TYPE_REG and begin.info.meta.size == 0:
				print "Unable to recover : " + str(['/'.join(parentPath)+begin.info.name.name])

		except IOError as e:
			print e
			continue

def main():

	#arg parser setup
	parser = argparse.ArgumentParser(description='Extract files from image.')
	parser.add_argument('image', metavar='image', type=str, nargs='+', help='image to extract image from')

	args = parser.parse_args()

	if args.image == None:
		print "No image given"
	
	try:
		os.remove("extractor.db")
	except:{}

	#sqlite3 database configuration
	conn = sqlite3.connect('extractor.db')
	conn.text_factory = str
	c = conn.cursor()
	c.execute('''CREATE TABLE recover ( Image, Start_address, MIME, Name, Create_time, Modified_time, Size);''')
	conn.commit()

	#analyze all images from arguments one by one
	for img in args.image:

		print "------------------------------------------------------------------------"
		print "[*] Analyzing image : {0}".format(img)
		imghandle = pytsk3.Img_Info(img)
		filesystemObject = pytsk3.FS_Info(imghandle)
		dirObject = filesystemObject.open_dir(path="/")
		recursive_extract(dirObject,[],img, conn)
		print "[+] Recovered Files in Directory : {0}".format('Recover_'+img)
		print "------------------------------------------------------------------------"

	# Final Output- Summary of Extraction
	print "\n\n"
	print "[*] Extraction Completed"
	print "Number of extracted files :{0}".format(str(len(images)+len(pdf)))
	print "images : {0}".format(str(len(images)))
	print "PDFs : {0}".format(str(len(pdf)))

	print "\n"
	print "List of Images extracted :"
	for i in images:
		print i

	print "\n"
	print "List of PDFs extracted :"
	for p in pdf:
		print p

	print "\n"
	print "More infomation on extracted files in database - extractor.db"
	print "Report in file Report - Report.txt"

	# Creating Report.txt
	report = open("Report.txt",'w')
	report.write("Extraction Report\n")
	report.write("Images processed : \n")
	cou=0
	for im in args.image:
		report.write("{0}. {1}\n".format(str(cou), im))
		cou+=1
	report.write("\n\nSummary----------------------------------------\n")
	report.write("Number of extracted files :{0}\n".format(str(len(images)+len(pdf))))
	report.write("images : {0}\n".format(str(len(images))))
	report.write("PDFs : {0}\n".format(str(len(pdf))))
	report.write("\n\nFiles ----------------------------------------\n")
	report.write ("( Image, Start_address, MIME, Name, Create_time, Modified_time, Size)\n")
	c.execute('SELECT * FROM recover')
	for x in c.fetchall():
		report.write("{0}\n".format(x))

	report.close()
	conn.close()

if __name__ == "__main__":
	main()