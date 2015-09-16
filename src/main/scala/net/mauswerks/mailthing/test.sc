val m = 16

def zero(i: Int, mask: Int)                 = (i & mask) == 0
//def mask(i: Int, mask: Int)                 = i & (complement(mask - 1) ^ mask)
def hasMatch(key: Int, prefix: Int, m: Int) = mask(key, m) == prefix
def unsignedCompare(i: Int, j: Int)         = (i < j) ^ (i < 0) ^ (j < 0)
def shorter(m1: Int, m2: Int)               = unsignedCompare(m2, m1)
def complement(i: Int)                      = (-1) ^ i
def bits(num: Int)                          = 31 to 0 by -1 map (i => (num >>> i & 1) != 0)
def bitString(num: Int, sep: String = "")   = bits(num) map (b => if (b) "1" else "0") mkString sep
def mask(l: Int, mask: Int) = (-1 ^ (1<<(32-mask))-1) & l

def highestOneBit(j: Int) = {
  var i = j
  i |= (i >>  1)
  i |= (i >>  2)
  i |= (i >>  4)
  i |= (i >>  8)
  i |= (i >> 16)
  i - (i >>> 1)
}

complement(4).toBinaryString
(-1 ^ (1<<(32-m))-1).toHexString


0xCC98600A.toBinaryString
mask(0xCC98600A, 32).toHexString

import scala.collection.generic

//def ip2long(s: String): Int = {
//}
//ip2long("1.2.3.5")

//val list = "217.172.190.23".split("\\.").toList
//
//list match {
//  case a :: b :: c :: d :: Nil =>
//    (a.toLong << 24) + (b.toLong << 16) + (c.toLong << 8) + d.toInt
//  case _ => 0
//}


//val e = scala.xml.XML.loadFile("/Users/topping/.m2/settings.xml")

