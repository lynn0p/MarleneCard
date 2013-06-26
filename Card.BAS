REM MarleneCard.bas, Copyright 2013 Owen Lynn <owen.lynn@hotmail.com>
REM Released under the GNU Public License V3

Option Explicit
Declare ApplicationID = "MarleneCard"

#include Card.def
#include rsa.def
#include SHA.def
#include AES.def
#include MISC.def

REM if you wonder why there's no _ separator, it's a reserved char
const SUCCESS                        = 0
const ERRORBADPIN                    = &H7f01
const ERRORBADPASS                   = &H7f02
const ERRORSETPUBKEYCHUNKTOOLONG     = &H7f03
const ERRORSETPUBKEYBADFLAG          = &H7f04
const ERRORSETCONTACTINFOTOOLONG     = &H7f05
const ERRORSETHOSTDATAHOSTTOOLONG    = &H7f06
const ERRORSETSERVERRESPBADFLAG      = &H7f07
const ERRORSETSERVERRESPCHUNKTOOLONG = &H7f08
const ERRORPARSEUNWRAPFAIL           = &H7f09
const ERRORPARSEDECRYPTFAIL          = &H7f0a
const ERRORPARSEMAGICBAD             = &H7f0b
const ERRORPARSEUNKNOWNCODE          = &H7f0c
const ERRORSETWALLETPASSTOOLONG      = &H7f0d

const SAFECHUNKLEN    = 210
const AES256BLOCKLEN  = 16
const ULONGZERO       = Chr$(0) + Chr$(0) + Chr$(0) + Chr$(0)
const CARDVERSION     = Chr$(&H00) + Chr$(&H00) + Chr$(&H01) + Chr$(&H00) ' Version 0.1.0.0
const CARDMAGIC       = Chr$(&Hef) + Chr$(&Hbe) + Chr$(&Had) + Chr$(&Hde) ' 0xdeadbeef
const SERVERMAGIC     = Chr$(&Hce) + Chr$(&Hfa) + Chr$(&Hed) + Chr$(&Hfe) ' 0xfeedface
const PACKETVERSION   = Chr$(&H01) + Chr$(&H00) + Chr$(&H00) + Chr$(&H00) ' 0x00000001
const CIPHERAES256    = Chr$(&H01)

const SERVERCODEHELLO   = &H0001
const SERVERCODEPAYMENT = &H0002
const SERVERCODEERROR   = &H8000

const CARDCODEPAYMENT = &H0001
const CARDCODEGOODBYE = &H0002

EEPROM PIN              as String*4
EEPROM PassphraseHash   as String*32
EEPROM WalletPassphrase as String
EEPROM PublicKey        as String
EEPROM ContactInfo      as String
EEPROM Hostname         as String
EEPROM Port             as Long
EEPROM Balance          as String*8
EEPROM TxFee            as String*8
EEPROM ReceivingAddress as String
EEPROM Txid             as String*32

EEPROM AES256Key        as String*32
EEPROM AES256IV         as String*16
EEPROM FromCardBuffer   as String
EEPROM FromServerBuffer as String
EEPROM PaymentStatus    as String*4
EEPROM LastServerError  as String*4

REM ------------------------------ BEGIN PRIVATE CALLS ------------------------------
Sub WasteTime()
  private i as Integer
  i = &H7fff
  while i > 0
    i = i - 1
  wend
End Sub

Function CheckSum(buf as String) as String*4
  private bufsum as String*4
  private sum as Long
  private i as Integer
  for i=1 to len(buf)
    sum = sum + asc(buf(i))
  next i
  bufsum(1) = Chr$(sum and &H000000ff)
  bufsum(2) = Chr$((sum and &H0000ff00) shr 8)
  bufsum(3) = Chr$((sum and &H00ff0000) shr 16)
  bufsum(4) = Chr$((sum and &Hff000000) shr 24)
  CheckSum = bufsum
End Function

Function WrapPacket(packet as String) as String
  private length as Integer
  private buf as String
  length = len(packet)
  buf = Chr$(length and &H00ff) + Chr$(length shr 8)
  buf = buf + CheckSum(packet)
  buf = buf + packet
  WrapPacket = buf
End Function

Function UnwrapPacket(wrapped as String) as String
  private ciphertext as String
  private sum as String*4
  ciphertext = Mid$(wrapped,7)
  sum = CheckSum(ciphertext)
  if sum(1) = wrapped(3) AND _
     sum(2) = wrapped(4) AND _
     sum(3) = wrapped(5) AND _
     sum(4) = wrapped(6) _
  then
    UnwrapPacket = ciphertext
  else
    UnwrapPacket = ""
  end if
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

Function doSayHello()
  private buffer as String
  call RandomString(AES256IV,16)
  call RandomString(AES256Key,32)
  buffer = CARDMAGIC
  buffer = buffer + PACKETVERSION
  buffer = buffer + Sha256Hash(Sha256Hash(CardSerialNumber()))
  buffer = buffer + CIPHERAES256
  buffer = buffer + AES256IV
  buffer = buffer + AES256Key
  call RsaExPKCS1Encrypt(buffer,PublicKey)
  doSayHello = LibError
  FromCardBuffer = WrapPacket(buffer)
End Function

Sub doMakePayment(amount as String*8, destaddr as String)
  private buffer as String
  private cipher as String

  buffer = CARDMAGIC
  buffer = buffer + PACKETVERSION
  buffer = buffer + Chr$(CARDCODEPAYMENT and &H00ff)
  buffer = buffer + Chr$((CARDCODEPAYMENT and &Hff00) shr 8)  
  buffer = buffer + amount
  buffer = buffer + Chr$(len(WalletPassphrase))
  buffer = buffer + WalletPassphrase
  buffer = buffer + Chr$(len(destaddr))
  buffer = buffer + destaddr
  
  cipher = AES256CBCEncrypt(buffer)  
  FromCardBuffer = WrapPacket(cipher)
End Sub

Sub doSayGoodbye()  
  private buffer as String
  private cipher as String
  
  buffer = CARDMAGIC
  buffer = buffer + PACKETVERSION
  buffer = buffer + Chr$(CARDCODEGOODBYE and &H00ff)
  buffer = buffer + Chr$((CARDCODEGOODBYE and &Hff00) shr 8)
  
  cipher = AES256CBCEncrypt(buffer)
  
  AES256Key = ""
  AES256IV = ""
  
  FromCardBuffer = WrapPacket(cipher)
End Sub

Sub doServerCodeHello(buf as String)
  Balance = Mid$(buf,1,8)
  TxFee = Mid$(buf,9,8)
  ReceivingAddress = Mid$(buf,17)
End Sub

Sub doServerCodePayment(buf as String)
  PaymentStatus = Mid$(buf,1,4)
  if (asc(PaymentStatus(4)) and &H80) = 0 then
    private txidhex as String
    txidhex = Mid$(buf,5)
    Txid = txidhex
  end if
End Sub

Sub doServerCodeError(buf as String)
  LastServerError = Left$(buf,4)
End Sub

Function doParseServerResponse()
  private cipherpacket as String
  cipherpacket = UnwrapPacket(FromServerBuffer)
  if len(cipherpacket) = 0 then
    doParseServerResponse = ERRORPARSEUNWRAPFAIL
    Exit Function
  else
    private plainpacket as String
    plainpacket = AES256CBCDecrypt(cipherpacket)
    if len(plainpacket) = 0 then
      doParseServerResponse = ERRORPARSEDECRYPTFAIL
      Exit Function
    else
      private magic as String*4
      magic = Left$(plainpacket,4)
      if magic <> SERVERMAGIC then
        doParseServerResponse = ERRORPARSEMAGICBAD
        Exit Function
      else
        private version as String*4
        private code as Integer
        private rest as String
        version = Mid$(plainpacket,5,4)
        REM TODO: check the version and scream if it's incompatible
        code = asc(plainpacket(9))
        code = code or (asc(plainpacket(10)) shl 8)
        rest = Mid$(plainpacket,11)
        if code = SERVERCODEHELLO then
          call doServerCodeHello(rest)
          LastServerError = ULONGZERO
        elseif code = SERVERCODEPAYMENT then
          call doServerCodePayment(rest)
          LastServerError = ULONGZERO
        elseif code = SERVERCODEERROR then
          call doServerCodeError(rest)
        else
          doParseServerResponse = ERRORPARSEUNKNOWNCODE
          Exit Function
        end if
      end if
    end if
  end if
  doParseServerResponse = SUCCESS
End Function
REM ------------------------------  END PRIVATE CALLS -------------------------------


REM ------------------------------- BEGIN PUBLIC API -------------------------------
Command &H01 &H00 Nuke()
  PIN = "0000"
  PassphraseHash = Sha256Hash("ChangeMe")
  WalletPassphrase = "ChangeMe"
  PublicKey = ""
  ContactInfo = ""
  Hostname = ""
  Port = 0
  Balance = ""
  TxFee = ""
  ReceivingAddress = ""
  Txid = ""
  
  AES256Key = ""
  AES256IV = ""
  FromCardBuffer = ""
  FromServerBuffer = ""
  PaymentStatus = ""
  LastServerError = ""
End Command

Command &H01 &H02 GetContactInfo(info as String)
  info = ContactInfo
End Command

Command &H01 &H04 GetHostData(p as Long, h as String)
  p = Port
  h = Hostname
End Command

Command &H01 &H06 GetVersion(version as String*4)
  version = CARDVERSION
End Command

Command &H01 &H20 SayHello(auth as String*4)
  if auth <> PIN then
    call WasteTime()
    SW1SW2 = ERRORBADPIN
  else
    private rc as Integer
    rc = doSayHello()
    if rc <> &H0000 then
      SW1SW2 = rc
    end if
  end if
End Command

Command &H01 &H22 GetBalance(auth as String*4, b as String*8)
  if auth <> PIN then
    call WasteTime()
    SW1SW2 = ERRORBADPIN
  else
    b = Balance
  end if
End Command

Command &H01 &H24 GetReceivingAddress(auth as String*4, bcaddr as String)
  if auth <> PIN then
    call WasteTime()
    SW1SW2 = ERRORBADPIN
  else
    bcaddr = ReceivingAddress
  end if
End Command

Command &H01 &H26 MakePayment(auth as String*4, amount as String*8, bcaddr as String)
  if auth <> PIN then
    call WasteTime()
    SW1SW2 = ERRORBADPIN
  else
    call doMakePayment(amount,bcaddr)
  end if
End Command

Command &H01 &H28 GetPaymentStatus(auth as String*4, status as String*4, t as String*32)
  if auth <> PIN then
    call WasteTime()
    SW1SW2 = ERRORBADPIN
  else
    status = PaymentStatus
    t = Txid
  end if
End Command

Command &H01 &H2a SayGoodbye(auth as String*4)
  if auth <> PIN then
    call WasteTime()
    SW1SW2 = ERRORBADPIN
  else
    call doSayGoodbye()
  end if
End Command

Command &H01 &H2c GetTxFee(auth as String*4, fee as String*8)
  if auth <> PIN then
    call WasteTime()
    SW1SW2 = ERRORBADPIN
  else
    fee = TxFee
  end if
End Command

Command &H01 &H2e CheckErrorCode(auth as String*4, status as String*4)
  if auth <> PIN then
    call WasteTime()
    SW1SW2 = ERRORBADPIN
  else
    status = LastServerError
  end if
End Command

Command &H01 &H30 SetServerResponse(auth as String*4, flag as Integer, chunk as String)
  if auth <> PIN then
    call WasteTime()
    SW1SW2 = ERRORBADPIN
  else
    if len(chunk) > SAFECHUNKLEN then
      SW1SW2 = ERRORSETSERVERRESPCHUNKTOOLONG
    else
      if flag = 0 then
        FromServerBuffer = chunk
      elseif flag = 1 then
        FromServerBuffer = FromServerBuffer + chunk
      else
        SW1SW2 = ERRORSETSERVERRESPBADFLAG
      end if
    end if
  end if
End Command

Command &H01 &H32 ParseServerResponse(auth as String*4)
  if auth <> PIN then
    call WasteTime()
    SW1SW2 = ERRORBADPIN
  else
    private rc as Integer
    rc = doParseServerResponse()
    if rc <> 0 then
      SW1SW2 = rc
    end if
  end if
End Command

Command &H01 &H34 GetCardRequestLength(auth as String*4, length as Long) 
  if auth <> PIN then
    call WasteTime()
    SW1SW2 = ERRORBADPIN
  else
    length = len(FromCardBuffer)
  end if
End Command

Command &H01 &H36 ReadCardRequest(auth as String*4,pos as Integer,chunk as String)
  if auth <> PIN then
    call WasteTime()
    SW1SW2 = ERRORBADPIN
  else
    private chunklen as Integer
    chunklen = len(FromCardBuffer)-pos+1
    if chunklen > SAFECHUNKLEN then
      chunklen = SAFECHUNKLEN
    end if
    chunk = Mid$(FromCardBuffer,pos,chunklen)
  end if
End Command


Command &H01 &H40 SetNewPIN(auth as String*32, new as String*4)
  if auth <> PassphraseHash then
    call WasteTime()
    SW1SW2 = ERRORBADPASS
  else
    PIN = new
  end if
End Command

Command &H01 &H42 SetNewPassphrase(auth as String*32, new as String*32)
  if auth <> PassphraseHash then
    call WasteTime()
    SW1SW2 = ERRORBADPASS
  else
    PassphraseHash = new
  end if
End Command

Command &H01 &H44 SetPublicKeyData(auth as String*32, flag as Integer, chunk as String)
  if auth <> PassphraseHash then
    call WasteTime()
    SW1SW2 = ERRORBADPASS
  else
    if len(chunk) > SAFECHUNKLEN then
      SW1SW2 = ERRORSETPUBKEYCHUNKTOOLONG
    else
      if flag = 0 then
        PublicKey = chunk
      elseif flag = 1 Then
        PublicKey = PublicKey + chunk
      else
        SW1SW2 = ERRORSETPUBKEYBADFLAG
      end if
    end if
  end if
End Command

Command &H01 &H46 SetContactInfo(auth as String*32, info as String)
  if auth <> Passphrasehash then
    call WasteTime()
    SW1SW2 = ERRORBADPASS
  else
    if len(info) > SAFECHUNKLEN then
      SW1SW2 = ERRORSETCONTACTINFOTOOLONG
    else
      ContactInfo = info
    end if
  end if
End Command

Command &H01 &H48 SetHostData(auth as String*32, p as Long, h as String)
  if auth <> PassphraseHash then
    call WasteTime()
    SW1SW2 = ERRORBADPASS
  else
    if len(h) > SAFECHUNKLEN then
      SW1SW2 = ERRORSETHOSTDATAHOSTTOOLONG
    else
      Hostname = h
      Port = p
    end if
  end if
End Command

Command &H01 &H4a SetWalletPassphrase(auth as String*32, wpass as String)
  if auth <> PassphraseHash then
    call WasteTime()
    SW1SW2 = ERRORBADPASS
  else
    if len(wpass) > SAFECHUNKLEN then
      SW1SW2 = ERRORSETWALLETPASSTOOLONG
    else
      WalletPassphrase = wpass
    end if
  end if
End Command
REM -------------------------------  END PUBLIC API  -------------------------------
