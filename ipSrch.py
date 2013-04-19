#!/usr/bin/python

import sys, getopt
from tables import *
from os.path import basename
import gzip
import datetime
import re
from operator import itemgetter, attrgetter
from itertools import groupby
import xml.sax
import unicodedata


def main(argv, scriptname='unknkown'):
   inputfilename = ''
   dbfilename = ''
   try:
      opts, args = getopt.getopt(argv,"hi:d:",["ifile=","dbfile="])
   except getopt.GetoptError:
      print scriptname+' -i <inputfile> -d <dbfile>'
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print scriptname+' -i <inputfile> -d <dbfile>'
         sys.exit()
      elif opt in ("-i", "--ifile"):
         inputfilename = arg
      elif opt in ("-d", "--dbfile"):
         dbfilename = arg
   if ( not inputfilename ) or ( not dbfilename ):
      print scriptname+' -i <inputfile> -d <dbfile>'
      sys.exit(2)

   searchIP( inputfilename, dbfilename )


class IP(IsDescription):
    ip        = StringCol(15)
    
class Revision(IsDescription):
    title     = StringCol(255)
    id        = UInt32Col()
    timestamp = Time64Col()
    ip        = StringCol(15)


def searchIP( inputfilename, dbfilename ):

  
  dbfile = openFile( dbfilename, "a" )
  try:
    group = dbfile.createGroup( '/', 'wikipedia' )
  except NodeError:
    group = dbfile.getNode( '/', 'wikipedia', classname='Group' )

  compressFilter = Filters( complevel=5, fletcher32=False )
  try:
    table = dbfile.createTable( group, re.sub('-|\.','_',basename(inputfilename)), Revision, filters=compressFilter )
  except NodeError:
    table = dbfile.getNode( group, re.sub('-|\.','_',basename(inputfilename)), classname='Table' )
    table.remove()
    table = dbfile.createTable( group, re.sub('-|\.','_',basename(inputfilename)), Revision, filters=compressFilter )

  fwgroup = dbfile.getNode( '/', 'firewallLogs', classname='Group' )
  iptable = dbfile.getNode( fwgroup, 'UniqueIPs', classname='Table' )



  def coroutine(func):
    def start( *args, **kwargs ):
      cr = func( *args, **kwargs )
      cr.next()
      return cr
    return start

  class MetaHistoryHandler( xml.sax.ContentHandler ):

    target = None,
    state = None,

    def __init__(self, target):
        self.target = target

    def startElement( self, name, attrs ):
        if( ( name == 'title' ) or
           ( name == 'id' ) or
           ( name == '!timestamp' ) or
           ( name == 'ip' ) ):
              self.state = name
        else: self.state = None

    def characters( self, text ):
        if( self.state != None ):
            nonUni = unicodedata.normalize('NFKD', text).encode('ascii','ignore')
            self.target.send( (self.state, nonUni) )

    def endElement( self, name ):
        self.state = None

  @coroutine
  def callback( table, iptable ):

    revision  = table.row
    title     = None
    id        = None
    timestamp = None
    ip        = None

    while True:
        event = (yield)
        revision[ event[0] ] = event[1]
        if( event[0] == 'title' ): title = event[1]
        if( event[0] == 'id' ): id = event[1]
        if( event[0] == 'timestamp' ): timestamp = event[1]
        if( event[0] == 'ip' ):
            revision['title'] = title
            revision['id'] = id
            revision['timestamp'] = timestamp
            for row in iptable.where( 'ip == "' + event[1] + '"' ):
              print title + ' ' + event[1]
              revision.append()
              revision = table.row
              break

  infile = gzip.GzipFile( inputfilename )
  xml.sax.parse( infile, MetaHistoryHandler(callback(table,iptable)) )



  dbfile.close()
  infile.close()

if __name__ == "__main__":
   main(sys.argv[1:], sys.argv[0])


