#!/usr/bin/env python
#
# duplicates.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

# https://github.com/nl5887/devf

import binascii
import struct
import zlib
import sys
import argparse

def main(argv):
    parser = argparse.ArgumentParser(
	prog='devf.py',
	description='devf extracts EnCase file format (e01) files.',
	formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True )
    args = parser.parse_args()

    with open(args.input, 'rb') as f:
	    header = f.read(8)
	    if (header != b"EVF\x09\x0d\x0a\xff\x00"):
		    print ('Invalid signature.')
		    sys.exit(0)
		    
	    print ('EVF file detected')
	    
	    b = f.read(1)
	    if (b!= b'\01'):
		    sys.exit()
		    
	    b = f.read(2)
	    i, = struct.unpack_from('<H', b)
	    print ("segment number {0}".format(i))
	    b, = struct.unpack_from('<H', f.read(2))
	    assert ( b == 0 )
	    
	    name = ''
	    while (name.rstrip(b'\x00')!='done'):	
		    s = struct.Struct('<16sQQ40xL')
		    name, offset, size, checksum, = s.unpack_from(f.read(s.size))
		    print ("{0} next: {1} size: {2} checksum:{3}".format(name, offset, size, checksum))
		    if (name.rstrip(b'\x00')=='volume'):
			    s = struct.Struct('<4xLLLL20x45x5xL')
			    chunks, sectorsperchunk, bytespersector, sectors, checksum, = s.unpack_from(f.read(s.size))
			    print ("chunks: {0} sectors per chunk: {1} bytes per sector: {2} sectors: {3} checksum: {4}".format(chunks, sectorsperchunk, bytespersector, sectors, checksum))
		    if (name.rstrip(b'\x00')=='sectors'):
			    #data = f.read(size - 76)
			    data = f.read(size-76)
			    chunksize = bytespersector * sectorsperchunk
			    with file(args.output, 'wb') as output:
				    print ('Writing to file {0}'.format(args.output))
				    while len(data):
					    try:
						    do = zlib.decompressobj()
						    uncompressed = do.decompress(data)
						    output.write(uncompressed)
						    data = do.unused_data
					    except zlib.error, e:
						    # could be because uncompressed is smaller then compressed, just write uncompressed output
						    output.write(data[:chunksize])
						    data = data[chunksize + 4:]
    
		    if (name.rstrip(b'\x00')=='table'):
			    s = struct.Struct('<L16xL')
			    #entries, checksum, = s.unpack_from(f.read(s.size))
			    #print "MD5 hash: {0}".format(binascii.hexlify(hash))
		    if (name.rstrip(b'\x00')=='digest'):
			    s = struct.Struct('<16s20s40xL')
			    md5hash, sha1hash, checksum, = s.unpack_from(f.read(s.size))
			    print ("MD5 hash: {0} SHA1 hash: {1}".format(binascii.hexlify(md5hash), binascii.hexlify(sha1hash)))
		    if (name.rstrip(b'\x00')=='hash'):
			    s = struct.Struct('<16s16xL')
			    hash, checksum, = s.unpack_from(f.read(s.size))
			    print ("MD5 hash: {0}".format(binascii.hexlify(hash)))
		    f.seek(offset)
	    
if __name__ == "__main__":
    main(sys.argv)