Usage:

  load [pwd]/sha.so
  set buffer abc123
  set sha512 [sha 512 $buffer]
  set sha512 [sha 512 -file sha.so]
  set sha384 [sha 384 -file sha.so]

Validated against NIST SHA512ShortMsg.rsp and SHA512LongMsg.rsp 2018-8-20.
