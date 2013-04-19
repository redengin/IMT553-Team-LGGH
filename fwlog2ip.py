#!/usr/bin/python

import sys, getopt
from tables import *
import datetime
import re
from operator import itemgetter, attrgetter
from itertools import groupby


def main(argv, scriptname='unknkown'):
   inputfilename = ''
   outputfilename = ''
   try:
      opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
   except getopt.GetoptError:
      print scriptname+' -i <inputfile> -o <outputfile>'
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print scriptname+' -i <inputfile> -o <outputfile>'
         sys.exit()
      elif opt in ("-i", "--ifile"):
         inputfilename = arg
      elif opt in ("-o", "--ofile"):
         outputfilename = arg
   if ( not inputfilename ) or ( not outputfilename ):
      print scriptname+' -i <inputfile> -o <outputfile>'
      sys.exit(2)

   extractIp( inputfilename, outputfilename )


class FirewallEntry(IsDescription):
    line        = UInt64Col()
    date        = Time64Col(20)
    src         = StringCol(15)
    src_port    = UInt16Col()
    dest        = StringCol(15)
    dest_port   = UInt16Col()
    protocol    = EnumCol( enum=Enum( {'tcp': 1L, 'udp': 0L} ), dflt='tcp', base='uint8' )

class IP(IsDescription):
    ip         = StringCol(15)
    

def extractIp( inputfilename, outputfilename ):
  # for each line in input map, IP with line number
  # export mapping to outputfile

  outputfile = openFile( outputfilename, "a" )
  try:
    group = outputfile.createGroup( '/', 'firewallLogs', inputfilename )
  except NodeError:
    group = outputfile.getNode( '/', 'firewallLogs', classname='Group' )

  try:
    table = outputfile.createTable( group, 'firewallEntries', FirewallEntry )
    table.cols.src.createCSIndex( );
  except NodeError:
    table = outputfile.getNode( group, 'firewallEntries', classname='Table' )

  r = re.compile( '(\w+)=("[^"]*"|\S+)' )
  inputfile = open( inputfilename )
  linecount = 0
  for line in inputfile:
    linecount += 1
    entry = table.row
    for k,v in r.findall( line ):
      if( k == 'time' ):
        pass #entry['date'] = datetime.strptime( v, "%Y-%b-%d %H:%M:%S" ).
      if( k == 'src' ):
        tokens = (v.split(':'))
        entry['src'] = tokens[0]
        entry['src_port'] = int(tokens[1])
      if( k == 'dst' ):
        tokens = (v.split(':'))
        entry['dest'] = tokens[0]
        entry['dest_port'] = int(tokens[1])
    entry['line'] = linecount
    entry.append()

  inputfile.close()

  table.flush()

  # sort the table
  table_sorted = table.copy( newparent=group, newname='SortedIPs', overwrite=True, sortby='src' );

  table_sorted.flush();


  try:
    table_unique = outputfile.createTable( group, 'UniqueIPs', IP )
  except NodeError:
    table_unique = outputfile.getNode( group, 'UniqueIPs', classname="Table" )

  for ip, set in groupby( table_sorted, key=itemgetter('src') ):
    entry = table_unique.row
    entry['ip'] = ip
    entry.append()

  outputfile.close()



if __name__ == "__main__":
   main(sys.argv[1:], sys.argv[0])


