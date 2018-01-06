#!/usr/bin/python 

###########################################################################
# DPI906 - Malware Analysis and Response                                  #
# Professor: Mohammad Faghani                                             #
# Group: Michael Zuccaro, Kashif Yamin, Mooven Soobaroyen, Ian Mu An Lin  #
###########################################################################
#                                 NOTICE                                  #
###########################################################################
# ALL RIGHTS RESERVED TO ORIGINAL AUTHOR: Shilpesh Trivedi                #
# CREDIT TO: Malware Analysis Using Python Script v1.1                    #
# AUTHOR AND COPYRIGHT TO: Shilpesh Trivedi                               #
# LINK: https://github.com/ShilpeshTrivedi/MAUPS                          #
###########################################################################
# ALSO CREDIT TO:                                                         #
# yarGen: https://github.com/Neo23x0/yarGen                               #
# mmbot - Malicious Macro Bot: https://github.com/egaus/MaliciousMacroBot #
###########################################################################

import requests
import re
import hashlib
import io
import pefile
import struct
import os
import os.path, time

def convert_bytes(num):
    # Converting
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0


def file_size(file_path):
    # File Path
    if os.path.isfile(file_path):
        file_info = os.stat(file_path)
        return convert_bytes(file_info.st_size)

try:
    # Asking For File
    cwd = os.getcwd()
    items = os.listdir(cwd)
    
    malfiles = []

    for item in items:
       if ".exe" in item:
          malfiles.append(item)
       elif ".xls" in item:
          malfiles.append(item)
       elif ".pdf" in item:
          malfiles.append(item)
       elif ".ppt" in item:
          malfiles.append(item)
       elif ".doc" in item:
          malfiles.append(item)
       elif ".docx" in item:
          malfiles.append(item)
       elif ".docm" in item:
          malfiles.append(item)
       else:
          pass
       
    print '+------------------------------------------------------------------------+'
    print '|                          DPI906 STATIC-2-YARA                          |'
    print '+------------------------------------------------------------------------+'
    
    print("  Files to Choose From: ")
    for files in malfiles:
       print("\t- " + files + "\n")

    f=raw_input("  Please enter the file to scan: ")
    
    try:
        fp= open(f)
        fp.close()
    except IOError:
        print "\n\tFile specified does not exist: '", f ,"'"
        exit()
 
    if ".exe" in f:
		
	    ## Image Type Anlaysis
	    IMAGE_FILE_MACHINE_I386=332
	    IMAGE_FILE_MACHINE_IA64=512
	    IMAGE_FILE_MACHINE_AMD64=34404
	    
	    fl=open(f, "rb")
	    print('\n')

	    s=fl.read(2)
	    if s!="MZ":
		print "ERROR: Not an EXE file"
	    else:
		fl.seek(60)
		s=fl.read(4)
		header_offset=struct.unpack("<L", s)[0]
		fl.seek(header_offset+4)
		s=fl.read(2)
		machine=struct.unpack("<H", s)[0]

		print '+------------------------------------------------------------------------+'
		print '|                              FILE INFORMATION                          |'
		print '+------------------------------------------------------------------------+'

		if machine==IMAGE_FILE_MACHINE_I386:
		    print "  - Image Type = IA-32 (32-bit x86)"
		    #fp=open('PE Analysis.txt','a')
		    #fp.write("Image Type = IA-32 (32-bit x86)")
		    #fp.close()
		elif machine==IMAGE_FILE_MACHINE_IA64:
		    print "  - Image Type = IA-64 (Itanium)"
		    #fp=open('PE Analysis.txt','a')
		    #fp.write("Image Type = IA-64 (Itanium)")
		    #fp.close()
		elif machine==IMAGE_FILE_MACHINE_AMD64:
		    print "  - Image Type = AMD64 (64-bit x86)"
		    #fp=open('PE Analysis.txt','a')
		    #fp.write("Image Type = AMD64 (64-bit x86)")
		    #fp.close()
		else:
		    print "  - Unknown architecture"
		
		print '\n  - File Size = ' + file_size(f)
		print '\n  - Last Modified Date = %s' % time.ctime(os.path.getmtime(f))
		print '\n  - Created Date = %s' % time.ctime(os.path.getctime(f))
		
		#fp=open('PE Analysis.txt','a')
		#fp.write('File Size = ' + file_size(f))
		#fp.write('\n\nLast Modified Date: %s' % time.ctime(os.path.getmtime(f)))
		#fp.write('\n\nCreated Date: %s' % time.ctime(os.path.getctime(f)))
		#fp.write('\n')
		print('\n')
		#fp.close()
	    #fl.close()

	    ## PE File Analysis"   
	    try:
		print '+------------------------------------------------------------------------+'
		print '|                              PE ANALYSIS                               |'
		print '+------------------------------------------------------------------------+'
		
		pe=pefile.PE(f)

		print '\n  - ImageBase = ' + hex(pe.OPTIONAL_HEADER.ImageBase)
		print '\n  - Address Of EntryPoint = ' + hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
		print '\n  - Number Of RvaAndSizes = ' + hex(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes )
		print '\n  - Number Of Sections = ' + hex(pe.FILE_HEADER.NumberOfSections) 

		fp=open('PE Analysis.txt','a')
		
		fp.write('- ImageBase = ' + hex(pe.OPTIONAL_HEADER.ImageBase))
		fp.write('\n\n- Address Of EntryPoint = ' + hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
		fp.write('\n\n- Number Of RvaAndSizes = ' + hex(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes ))
		fp.write('\n\n- Number Of Sections = ' + hex(pe.FILE_HEADER.NumberOfSections))
		fp.write('\n')
		fp.write('\n')

		## List Import Sections"
		print '\n  Listing Sections...\n'
		fp.write('\n')
		fp.write('\n')
		fp.write('  Listing Sections \n\n')

		for section in pe.sections:
		    print('\t  ' + section.Name.decode('utf-8'))
		    print("\t\t- Virtual Address: " + hex(section.VirtualAddress))
		    print("\t\t- Virtual Size: " + hex(section.Misc_VirtualSize))
		    print("\t\t- Raw Size: " + hex(section.SizeOfRawData))
		    fp.write('\n ' + section.Name.decode('utf-8'))
		    fp.write("\n\n\t- Virtual Address: " + hex(section.VirtualAddress))
		    fp.write("\n\n\t- Virtual Size: " + hex(section.Misc_VirtualSize))
		    fp.write("\n\n\t- Raw Size: " + hex(section.SizeOfRawData))

		    print '\n'

		## List Import DLL"
		fp.write('\n')
		fp.write('\n')
		fp.write('\n')
		fp.write('\n  Listing imported DLLs...')
		print '  Listing imported DLLs...\n'
		for lst in pe.DIRECTORY_ENTRY_IMPORT:
		    print ('\n  '+lst.dll.decode('utf-8'))
		    fp.write('\n  '+lst.dll.decode('utf-8'))
		    for s in lst.imports:
			print ("\t - %s at 0x%08x" % (unicode(s.name).decode('utf-8'), s.address))
			fp.write('\n\n' + "\t - %s at 0x%08x" % (unicode(s.name).decode('utf-8'), s.address)+ '\n',)


		print '\n  Listing Header Members...'

		fp=open('PE Analysis.txt','a')
		fp.write('\n')
		fp.write('\n')
		fp.write('\n')
		fp.write('\n  Listing Header Members...')
		fp.write('\n')
		
		for headers in pe.DOS_HEADER.dump():
		    print '\n\t' + headers
		    fp.write('\n')
		    fp.write('\n\t' + headers)
		    
		print '\n'
		fp.close()

		for ntheader in pe.NT_HEADERS.dump():
		    print '\n\t' + ntheader
		    fp=open('PE Analysis.txt','a')
		    fp.write('\n')
		    fp.write('\n\t' + ntheader)

		print '\n  Listing Optional Headers...'

		fp=open('PE Analysis.txt','a')
		fp.write('\n')
		fp.write('\n')
		fp.write('\n')
		fp.write('\n  Listing Optional Headers...')
		fp.write('\n')
		for optheader in pe.OPTIONAL_HEADER.dump():
		    print '\n\t' + optheader
		    fp.write('\n')
		    fp.write('\n\t' + optheader)

		print '\n  - See PE Analysis.txt\n'
		
	    except:
		print '\n' + f + ' DOS Header magic not found.'
		
	#### Strings Analysis Extracting Atrings From File ####

	    print '+------------------------------------------------------------------------+'
	    print '|                             STRINGS ANALYSIS                           |'
	    print '+------------------------------------------------------------------------+'
	    
	    os.system("peframe --strings " + f + " > ./strings/strings.txt")

	    print '  - See ./strings/strings.txt\n'
	      
	    print '+------------------------------------------------------------------------+'
	    print '|                                  HASHES                                |'
	    print '+------------------------------------------------------------------------+'
	    with io.open(f, mode="rb") as fd:
		content = fd.read()
		md5=hashlib.md5(content).hexdigest()
		sha256=hashlib.sha256(content).hexdigest()
	    
	    print '  - SHA256: ', sha256
	    print '  - MD5: ', md5
	    
	    print '\n'
	    print '+------------------------------------------------------------------------+'
	    print '|                       POTENTIAL MALICIOUS IoC\'s                        |'
	    print '+------------------------------------------------------------------------+'
	    print ''
	    print '  Loading Potential Malicious IoC\'s, this may take a few minutes...'

	    # Check if directory exists
	    if os.path.exists("./reqFiles/file2analyze/"):
	       pass
	    else:
	       os.system("mkdir ./reqFiles/file2analyze/")
	   
	    # Remove existing files
	    dirPath = "./reqFiles/file2analyze/"
	    fileList = os.listdir(dirPath)
	    for fileName in fileList:
	       os.remove(dirPath + fileName)

	    os.system("cp {} ./reqFiles/file2analyze/".format(f))

	    os.system("python ./reqFiles/yarGen.py -m ./reqFiles/file2analyze/ --nr > /dev/null")

	    print("\n")
	    print("  Results: \n")

	    with open('./strings/stringsFound.txt', 'r') as myfile:
	       data = myfile.read()

	    import re
	    potIoc = re.findall(r'\"(.+?)\"', data)
	    counter = 0

	    for ioc in potIoc:
	       counter = counter + 1
	       print("  " + str(counter) + ": " + str(ioc))

    else:
            print '\n'
            
            print '+------------------------------------------------------------------------+'
            print '|                              FILE INFORMATION                          |'
	    print '+------------------------------------------------------------------------+'
            print '\n  - File Size = ' + file_size(f)
	    print '\n  - Last Modified Date = %s' % time.ctime(os.path.getmtime(f))
	    print '\n  - Created Date = %s' % time.ctime(os.path.getctime(f))

            print '\n'	
            print '+------------------------------------------------------------------------+'
	    print '|                           MMBOT ANALYSIS                               |'
	    print '+------------------------------------------------------------------------+'
            print '  Running mmbot_analysis.py script, this may take a moment...'
            os.system("python ./reqFiles/mmbot_analysis.py {}".format(f))
	
            print '\n'	
            print '+------------------------------------------------------------------------+'
	    print '|                              PE ANALYSIS                               |'
	    print '+------------------------------------------------------------------------+'
            os.system("peframe {}".format(f))
            
            print '\n'
            print '+------------------------------------------------------------------------+'
	    print '|                             STRINGS ANALYSIS                           |'
	    print '+------------------------------------------------------------------------+'
	    
	    os.system("peframe --strings " + f + " > ./strings/strings.txt")

	    print '  - See ./strings/strings.txt\n'
	      
	    print '+------------------------------------------------------------------------+'
	    print '|                                  HASHES                                |'
	    print '+------------------------------------------------------------------------+'
	    with io.open(f, mode="rb") as fd:
		content = fd.read()
		md5=hashlib.md5(content).hexdigest()
		sha256=hashlib.sha256(content).hexdigest()
	    
	    print '  - SHA256: ', sha256
	    print '  - MD5: ', md5
	    
	    print '\n'
	    print '+------------------------------------------------------------------------+'
	    print '|                       POTENTIAL MALICIOUS IoC\'s                        |'
	    print '+------------------------------------------------------------------------+'
	    print ''
	    print '  Loading Potential Malicious IoC\'s, this may take a few minutes...'

	    # Check if directory exists
	    if os.path.exists("./reqFiles/file2analyze/"):
	       pass
	    else:
	       os.system("mkdir ./reqFiles/file2analyze")
	    
	    # Remove existing files
	    dirPath = "./reqFiles/file2analyze/"
	    fileList = os.listdir(dirPath)
	    for fileName in fileList:
	       os.remove(dirPath + fileName)

	    os.system("cp {} ./reqFiles/file2analyze/".format(f))

	    os.system("python ./reqFiles/yarGen.py -m ./reqFiles/file2analyze/ --nr > /dev/null")

	    print("\n")
	    print("  Results: \n")

	    with open('./strings/stringsFound.txt', 'r') as myfile:
	       data = myfile.read()

	    import re
	    potIoc = re.findall(r'\"(.+?)\"', data)
	    counter = 0

	    for ioc in potIoc:
	       counter = counter + 1
	       print("  " + str(counter) + ": " + str(ioc))

    counter2 = 0

    filetest = open('generated_yara.yar', 'w+')

    splitfileName = f.split(".")

    filetest.write("rule " + splitfileName[0] + " : malware {\n")
    
    rows = []

    for line in open('./strings/stringsFound.txt', 'rb'):
       rows.append(line.strip())

    fClean = open('./strings/stringsFoundClean.txt', 'w+')

    for row in rows:
       fClean.write("\t\t" + str(row) + '\n')
    
    fClean.close()

    with open('./strings/stringsFoundClean.txt', 'r') as myfile3:
       data3 = myfile3.read()

    # Meta
    filetest.write("\tmeta:\n")
    filetest.write("\t\tdescription = \"Yara Rule automatically generated by dpi906_staticAnalysis.py.\"\n")
    filetest.write("\t\tmd5 = " + "\"" + str(md5) + "\"\n")
    filetest.write("\t\tfilename = " + "\"" + f + "\"\n")
    filetest.write("\t\tauthor = \"dpi906_staticAnalysis.py\"\n")

    # Strings
    filetest.write("\tstrings:\n")
    filetest.write(data3 + "\n")

    # Conditions
    filetest.write("\tcondition:\n")
    filetest.write("\t\tall of them\n")
    filetest.write("}\n")

    #print filetest
    filetest.close()

    #print(data)

    print '\n'
    print '+------------------------------------------------------------------------+'
    print '|                             CREATED YARA RULE                          |'
    print '+------------------------------------------------------------------------+'
    print ''
    with open('generated_yara.yar', 'r') as myfile2:
       data2 = myfile2.read()

    print '  Yara File Name: generated_yara.yar'
    print '  Contents of generated Yara file:\n'
    print '  ' + data2

except:
    print '\n\nError Encountered!'
