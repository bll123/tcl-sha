Usage:

  load [pwd]/sha.so
  set buffer abc123
  set sha512 [sha 512 $buffer]
  set sha512 [sha 512 -file sha.so]
  set sha384 [sha 384 -file sha.so]
  set sha512/224 [sha 512/224 -file sha.so]
  set sha512/256 [sha 512/256 -file sha.so]

Validated against NIST:  2018-8-20
  SHA512ShortMsg.rsp, SHA512LongMsg.rsp
  SHA384ShortMsg.rsp, SHA384LongMsg.rsp
  SHA512_256ShortMsg.rsp, SHA512_256LongMsg.rsp
  SHA512_224ShortMsg.rsp, SHA512_224LongMsg.rsp
  SHA256ShortMsg.rsp, SHA256LongMsg.rsp
  SHA224ShortMsg.rsp, SHA224LongMsg.rsp
