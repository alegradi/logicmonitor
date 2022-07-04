// Taken from the LogicMonitor SSL_Certificates script

// Begin with getting IPs. Requires the linux_ssh_info_extended auto-discovery script
def ips = hostProps.get("auto.discovered.ips").split(",")

// Create a map of all common SSL ports with their names.
def ports = ["HTTP - SSL"           : 443,
             "Logstash 5044 - SSL"  : 5044,
             "Logstash 5514 - SSL"  : 5514,
             "Logstash 5515 - SSL"  : 5515,
             "Logstash 5516 - SSL"  : 5516,
             "Kibana 5601 - SSL"    : 5601,
             "Apache Tomcat - SSL"  : 8443,
             "ELK test 9200 - SSL"  : 9200,
             "ELK test 9300 - SSL"  : 9300,
             "ELK test 9600 - SSL"  : 9600]

// Loop through each port...
ips.each { ip ->
    ports.each { name, port ->
        // There is a high chance at least some of these ports won't connect!
        try {
            // Create a socket.
            def socket = new Socket()

            // Attempt a connection to our host and port with a one second timeout.
            socket.connect(new InetSocketAddress(ip, port), 1000)

            // The socket could connect! The port is open! Print the instance.
            println "$ip:$port##$name"

            // Close the socket.
            socket.close()
        }
        catch (e) {
            // Port isn't open
        }
    }
}
