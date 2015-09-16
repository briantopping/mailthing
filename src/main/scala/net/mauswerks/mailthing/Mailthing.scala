package net.mauswerks.mailthing

import java.io.{FileInputStream, FileOutputStream, ObjectInputStream, ObjectOutputStream}
import java.util.Date
import javax.mail._

import scala.annotation.tailrec
import scala.collection.immutable.TreeMap
import scala.util.{Failure, Success, Try}

/*
 * Widget that creates a blacklist from an IMAP mailbox, like your junk folder.
 *
 * Currently just generates a postmap format CIDR blacklist with the number of current hits in it.  This number can't
 * be accurate until future mails that are blacklisted using the map increment the hit count.
 *
 * Besides that, the next major increment of this thing is to update the Berkeley DB directly. When we can do that,
 * we will merge the old contents of that DB with the output of extractIPMap for a sorted input to clean().  This
 * will merge down the blocks properly, which will ensure that fewer gaps mean fewer spams slipping through.
 *
 * Do these next steps after getting mail server moved. Then we can code to a recent version of Berkeley DB and
 * have it delete the messages that it already processed.
 */
object Mailthing {
  case class NetworkHistory(count: Int = 0, lastSeen: Date = new Date()) {
    def incr = NetworkHistory(count + 1, new Date())
  }
  type NetworkMap = TreeMap[Network, NetworkHistory]

  case class Network(number: Long, bits: Int) {
    require(Network.mask(number, bits) == number)

    def contains(that: Network) = bits <= that.bits && Network.mask(that.number, this.bits) == number

    override def toString: String =
       s"${String.valueOf((number & 0xFF000000) >> 24)}" +
      s".${String.valueOf((number & 0x00FF0000) >> 16)}" +
      s".${String.valueOf((number & 0x0000FF00) >> 8)}" +
      s".${String.valueOf(number & 0x000000FF)}/$bits"
  }

  object Network {
    def mask(l: Long, mask: Int) = (-1 ^ (1 << (32 - mask)) - 1) & l

    implicit def orderByNetwork[A <: Network]: Ordering[A] = Ordering.by(n => n.number)

    // create a /32 Network from a string
    def apply(s: String): Network = {
      s.split("\\.").toList match {
        case a :: b :: c :: d :: Nil =>
          Network((a.toLong << 24) + (b.toLong << 16) + (c.toLong << 8) + d.toLong, 32)
      }
    }

    // create a CIDR Network based on an existing Network and the number of bits
    def apply(n: Network, bits: Int) = {
      new Network(mask(n.number, bits), bits)
    }
  }

  /**
   * Regex parser for JavaMail Message objects. Finds "Recieved" headers, pulls the source IP, and populates a SortedMap
   * @param msgs List of JavaMail Message objects
   * @param result SortedMap of Network objects with hit counts as values
   * @return the result parameter when the msgs list is empty
   */
  @tailrec
  def extractIpMap(msgs: List[Message], result: NetworkMap = TreeMap.empty): NetworkMap = {
    def addHit(result: NetworkMap, binIp: Network): (Network, NetworkHistory) = {
      binIp -> (result getOrElse(binIp, NetworkHistory())).incr
    }

    val regex = """\[(\d+\.\d+\.\d+\.\d+)\]""".r
    msgs match {
      case Nil => result
      case head :: tail =>
        (for (regex(ipval) <- regex findFirstIn head.getHeader("Received").tail.head) yield ipval) match {
          case None => result
          case Some(x) =>
            val binIp = Network(x)
            extractIpMap(tail, result + addHit(result, binIp))
        }
    }
  }

  // try to read from the serialization file, return success or failure based on result
  def deserializeFromDisk[A <: Traversable[Any]](filename: String): Try[A] = {
    var ois: Option[ObjectInputStream] = None
    try {
      ois = Some(new ObjectInputStream(new FileInputStream(filename)))
      Success(ois.get.readObject.asInstanceOf[A])
    }
    catch {
      case e: Exception => Failure(e)
    } finally {
      ois.foreach { _.close() }
    }
  }

  def serializeToDisk[A <: Traversable[Any]](cleaned: A, filename: String): Unit = {
    if (cleaned.nonEmpty) {
      val oos = new ObjectOutputStream(new FileOutputStream(filename))
      oos.writeObject(cleaned)
      oos.close()
    }
  }

  def processMailbox(protocol: String, server: String, account: String, password: String, folderName: String, processor: (List[Message], NetworkMap) => NetworkMap): Try[NetworkMap] = {
    val props = System.getProperties
    props.setProperty("mail.store.protocol", protocol)
    props.setProperty("mail." + protocol + ".ssl.trust", server)

    val session = Session.getDefaultInstance(props, null)
    val store = session.getStore(protocol)
    try {
      store.connect(server, account, password)
      val folder = store.getFolder(folderName)
      folder.open(Folder.READ_ONLY)

      Success(processor(folder.getMessages.toList, TreeMap.empty))
    } catch {
      case e: Exception =>
        print(e.printStackTrace())
        Failure(e)
    } finally {
      store.close()
    }
  }

  /**
   * Aggregate CIDR blocks to get around spammers who rotate their IP addresses.
   *
   * This currently pays no attention to registry data because it's intentionally inaccurate when the ISP and the spammer
   * collude. That said, we could easily start with the registry netblock instead of /32.
   *
   * Once the raw messages have been put into a map of the source address and hit count, apply the keys of that map
   * sequentially to the result map. Critically, the result map is a reverse sorted map such that the head of the keys
   * is always the largest (and closest) neighbor to the current key.
   *
   * Matches are always added to the result map starting with the count they had in the ipMap, which may be greater than 1.
   *
   * @param newMap SortedMap of Network elements with a count of the number of hits recorded
   * @return SortedMap of CIDR blocks and hits within the block
   */
  def merge(savedMap: NetworkMap, newMap: NetworkMap, matchBits: Int): NetworkMap = {
    @tailrec
    def recur(merged: NetworkMap, mergeKeys: List[Network]): NetworkMap = {
      mergeKeys match {
        case Nil => merged
        case head :: tail =>
          val i = merged.keysIteratorFrom(Network(head, 23))
          if (i.hasNext) {
            // TODO not happy with this, it should use some bitwise magic rather than iteration...
            val item = i.next()
            (item.bits to matchBits by -1).find(e => {
              Network(item, e).contains(head)
            }) match {
              // if so, store the current count, delete the old head and add the new widened
              // head with the sum of the old count and the new network count.
              case Some(x) =>
                val tuple: (Network, NetworkHistory) = Network(head, x) -> NetworkHistory(count = newMap(head).count + merged(item).count)
                recur(merged - item + tuple, tail)
              // if not, add a new element
              case None =>
                recur(merged + (head -> newMap(head)), tail)
            }
          } else {
            recur(merged + (head -> newMap(head)), tail)
          }
      }
    }
    recur(savedMap, newMap.keys.toList)
  }

  def main(args: Array[String]) {
    case class Config(protocol: String = "imaps", server: String = "", username: String = "", password: String = "", folder: String = "", bits: Int = 23)
    val parser = new scopt.OptionParser[Config]("mailthing") {
      opt[String]('p', "protocol") action { (x, c) =>
        c.copy(protocol = x)
      } validate { x =>
        if (x matches "imaps?") success else failure("protocol option requires 'imap' or 'imaps'")
      } text "server protocol ('imap' or 'imaps', default 'imaps')"
      opt[String]('s', "server") action { (x, c) =>
        c.copy(server = x) } text "server FQDN"
      opt[String]('u', "username") action { (x, c) =>
        c.copy(username = x) } text "account name on server"
      opt[String]('P', "password") action { (x, c) =>
        c.copy(password = x) } text "account password"
      opt[String]('f', "folder") action { (x, c) =>
        c.copy(folder = x) } text "folder on server"
      opt[Int]('b', "bits") action { (x, c) =>
        c.copy(bits = x) } text "CIDR bits to match (default is 23)"
    }

    parser.parse(args, Config()) foreach { c =>
      val HISTORY_FILE_NAME: String = "history"
      val savedMap: NetworkMap = deserializeFromDisk(HISTORY_FILE_NAME).getOrElse(TreeMap.empty)
      val newMap: NetworkMap = processMailbox(c.protocol, c.server, c.username, c.password, c.folder, extractIpMap).getOrElse(TreeMap.empty)
      val merged = merge(savedMap, newMap, c.bits)

      serializeToDisk(merged, HISTORY_FILE_NAME)

      merged.keys.toList.sorted.foreach(key => println(s" $key REJECT ${merged(key).count} spam(s) from your network!"))
    }
  }
}
