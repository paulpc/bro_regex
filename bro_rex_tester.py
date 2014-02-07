#!/usr/bin/python
import re,os, time, sys

def create_regex(bfname, bfields, bformat, rex_dict):
  """creates the regular expression to match the bro log file based on:
  - the bro log file name
  - list of bro fields from this file
  - list of format for the bro fields in this file
  - dictionary of regular expressions corresponding to the field formats"""
  regex=r'(bro_'+bfname.split('.')[0]+r')\:[\s\t]+'
  regex_array=[]
  for field in bfields:
    regex_array.append(rex_dict[bformat[field]])
  regex+='\t'.join(regex_array)
  return regex

def auto_debug_regex(line,bfname,debug_info):
  """looks at a regular expression and tries to debug which part of it doesn't match the bro line. It takes as paramenters:
  - the bro line
  - the bro log file name
  - the debug information (a complex element containing regular expression and field information for this bro log file"""
  prev_working_regex=r'.*'
  for n in range(len(debug_info)):
    regex=r'(bro_'+bfname.split('.')[0]+r')\:[\s\t]+'
    regex_array=[]
    for i in range(n):
      regex_array.append(debug_info[i][2])
    regex+='\t'.join(regex_array)
    if re.match(regex,line):
      prev_working_regex=regex
    else:
      print "getting stuck on: ",n,debug_info[n]
      print re.findall(prev_working_regex,line)
      print line
      time.sleep(0.5)
      break
  
# regular expression dictionary for fields  
rex_bb={'time':r'(\d+\.\d+|\-)',
	'string':r'(.+?)',
	'addr':r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\-|[0-9a-f\:]+)',
	'port':r'(\d{1,5}|\-)',
	'enum':r'(.+?)',
	'bool':r'(F|T|\-)',
	'count':r'(\d+|\-)',
	'vector[string]':r'(.+?)',
	'vector[interval]':r'([0-9\-\,]+)',
	'vector[addr]':r'([\d\.\,\-]+)',
	'table[addr]':r'([\d\.\,\-]+|\(empty\))',
	'table[string]':r'(.+?)',
	'table[enum]':r'(.+?)',
	'interval':r'(\d+\.\d+|\-)',
	'double':r'(\d+\.\d+|\-)'}

bro_rex={}
bro_rex_debug={}

if len(sys.argv)>1 and os.path.isdir(sys.argv[1]):
  bro_logs_dir=sys.argv[1]
else:
  sys.exit('usage:\n\t bro_rex_tester.py [bro_logs_folder]')
# loading formats
for filename in os.listdir(bro_logs_dir):
  if re.match('\w+\.log',filename):
    bro_fields=[]
    bro_forms=[]
    for line in open(bro_logs_dir+'/'+filename,'r+'):
      if line.startswith('#fields'):
	bro_fields=line.strip().split('\x09')
	bro_fields.remove('#fields')
	#print '[+] found the following fields',bro_fields
      elif line.startswith('#types'):
	bro_forms=line.strip().split('\x09')
	bro_forms.remove('#types')
	#print '[+] found the following formats',bro_forms
      elif not line.startswith('#'):
	break
    bro_format={}
    if len(bro_fields)==len(bro_forms):
      #print '[+] reading the format for '+filename
      for i in range(len(bro_fields)):
	bro_format[bro_fields[i].strip()]=bro_forms[i].strip()
      bro_rex[filename]=create_regex(filename,bro_fields,bro_format,rex_bb)
      debug_info=[]
      for field in bro_fields:
        debug_info.append([field, bro_format[field], rex_bb[bro_format[field]]])
      bro_rex_debug[filename]=debug_info
    else:
      print '[-] Unable to get a goood reading on the format of '+filename
output=open('regular_expressions.txt','wb')
output.write('# list of the regular expressions corresponding to the files in the bro log folder')
for filename in bro_rex.keys():
  print '[*] analyzing the regex for '+filename,
  match_lines=0
  unmatch_lines=0
  for line in open(bro_logs_dir+'/'+filename):
    if not line.startswith('#'):
      new_line='bro_'+filename.split('.')[0]+': '+line
      #print bro_rex[filename],new_line
      if re.match(bro_rex[filename],new_line):
	match_lines+=1
	#print '[+] matched: '+lines
      else:
	unmatch_lines+=1
	auto_debug_regex(new_line,filename,bro_rex_debug[filename])
  print str(match_lines*100.00/(match_lines+unmatch_lines))
  if match_lines*100 / (match_lines+unmatch_lines) < 97.0:
    print bro_rex[filename]
  else:
    output.write('<pattern id="BRO'+filename.split('.')[0]+'Event">'+bro_rex[filename].replace('\t','\\t')+'</pattern>\n')
output.close
