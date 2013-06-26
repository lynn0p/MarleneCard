REM Copyright 2013 Owen Lynn <owen.lynn@hotmail.com>
REM Released under the GNU Public License V3
Option Explicit

#include Card.def
#Include COMMANDS.DEF
#Include COMMERR.DEF
#include MISC.DEF
#Include CARDUTIL.DEF

#include RSA.def
#include AES.def

PUBLIC idx as Integer
PUBLIC appflag as Integer
PUBLIC pkhex as String
PUBLIC pubkey as String
PUBLIC buf as String
PUBLIC buf1 as String
PUBLIC AES256Key as String*32
PUBLIC AES256IV as String*16

Declare Function DecodeHexString(inbuf as String) as String
Declare Function AES256CBCEncrypt(in as String) as String
Declare Function AES256CBCDecrypt(in as String) as String

REM  Execution starts here
REM replace this public key with one of your own for testing
pkhex = "308202080282020100d076c2d645a2429697a4077c7b074dce9f266121a21ba55c735b006f5d8d0f"
pkhex = pkhex + "f515266e4e082b71cd9886d7bb3c75710adefb80fe53b1323110bff0612fa92cb91de300dc550ba5"
pkhex = pkhex + "f5d662ccc3caa99dd39e50b2421faff5185499daeb6fffe64daf65abc8bc1bc1af4968f7c6a287b0"
pkhex = pkhex + "d03b12bd5a565a77cfaa8b05bb82a4f826361a1b864ba75c186966a18710a661d21f06297489cf99"
pkhex = pkhex + "acf280fcfcb8db203358e3f222c3da767ec7b13c8d2317137be1738696ad5f771d629863138be811"
pkhex = pkhex + "a4f25b73267c74fa4870152f06ff6a8f336c0e84a451d73794294c479a121dac313d3a10b86d8c7b"
pkhex = pkhex + "6ae95743040d79cc274b2d463ff775aa33df65ce6b875535a0ef083774662a7a049d162eccd739f6"
pkhex = pkhex + "cba51fcb998760ac17f72bd38daea69c2d8c927dc7d56952766ff3a31c993be2d52e39af5c8d6007"
pkhex = pkhex + "fb597fa14fc7ac0a39440f6dcae6990c12ed110d98b745c0063746e1d91f16860f15f03878bc8b28"
pkhex = pkhex + "191da9c2d641964aff111047f2a388f68c2843ca41f12b00f10b37427a8298e3959f74478fcb3890"
pkhex = pkhex + "796d17fece6e54f903d18c5bd9cbfc94d279ad1c5c233fc2e46b56aa78d259870ce599aab2302737"
pkhex = pkhex + "57eaf159cf5b89407c4816d1e6065038284dd1f394d2350d52a2a8979884cb9ebed7a1c28952c32b"
pkhex = pkhex + "fc5d37eea9b12e03b18b006dfea7659e608185e1294c3b50e29edb3c57fbf83d91bb3e2ec7ec90f0"
pkhex = pkhex + "5d020103"
pubkey = DecodeHexString(pkhex)

REM test the AESCBC encrypt and decrypt calls
AES256Key = "01234567890123456789012345678901"
AES256IV = "0123456789012345"
buf = AES256CBCEncrypt("The quick brown fox, jumped over the lazy dog.")
buf1 = AES256CBCDecrypt(buf)

REM talking to the card
Call WaitForCard()
ResetCard : Call CheckSW1SW2()

call Nuke() : Call CheckSW1SW2()

idx=1
appflag=0
while idx < len(pubkey)
   private chunk as String
   private chunklen as Integer
   chunklen = len(pubkey) - (idx-1)
   if chunklen > 250 then
      chunklen = 250
   end if
   chunk = Mid$(pubkey,idx,chunklen)
   call SetPublicKeyData("0000",appflag,chunk) : Call CheckSW1SW2()
   if appflag = 0 Then
      appflag = 1
   end if
   idx = idx + len(chunk)
wend

call SayHello("0000") : Call CheckSW1SW2()
call GetCardRequestLength("0000",chunklen) : Call CheckSW1SW2()
call ReadCardRequest("0000",1,buf) : Call CheckSW1SW2()

print buf

REM ---------------- PRIVATE CALLS ----------------------
Function DecodeHexString(inbuf as String) as String
   private hextbl as String
   private i,j,k as Integer
   k = 0
   hextbl = "0123456789abcdef"
   For i=1 to len(inbuf)
      For j=1 to len(hextbl)
         If inbuf(i) = hextbl(j) Then
            exit for
         end if
      Next j

      k = k or (j-1)
      if (i mod 2) = 1 Then
         k = k shl 4
      else
         DecodeHexString = DecodeHexString + Chr$(k)
         k = 0
      end if
   next i
End Function

Function XORBLOCK(b1 as String*16, b2 as String*16) as String*16
  private i as Integer
  private out as String*16
  for i=1 to 16
    out(i) = b1(i) xor b2(i)
  next i
  XORBLOCK = out
End Function

Function AES256CBCEncrypt(in as String) as String
  private i as Integer
  private out as String
  private firstblock as Byte
  
  i = 1
  firstblock = 1
  out = ""
  while (i <= len(in))
    private block1 as String*16
    private block2 as String*16
    private cipherblock as String*16

    block1 = ""
    block1 = Mid$(in,i,16)
    if firstblock = 1 then
      firstblock = 0
      block2 = XORBLOCK(block1,AES256IV)
    else
      block2 = XORBLOCK(block1,cipherblock)
    end if
    cipherblock = AES(256,AES256Key,block2)
    out = out + cipherblock
    i = i + 16
  wend
  
  AES256CBCEncrypt = out
End Function

Function AES256CBCDecrypt(in as String) as String
  private i as Integer
  private out as String
  private firstblock as Byte
  
  i = 1
  firstblock = 1
  out = ""
  while (i <= len(in))
    private block1 as String*16
    private block2 as String*16
    private block3 as String*16
    private plainblock as String*16

    block1 = ""
    block1 = Mid$(in,i,16)
    block2 = AES(-256,AES256Key,block1)
    if firstblock = 1 then
      firstblock = 0
      plainblock = XORBLOCK(block2,AES256IV)
    else
      plainblock = XORBLOCK(block2,block3)
    end if
    block3 = block1
    out = out + plainblock
    i = i + 16
  wend
  
  AES256CBCDecrypt = out
End Function