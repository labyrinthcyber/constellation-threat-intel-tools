# Constellation Threat Intel Tools

The Threat Intel plugins build upon the functionality of Constellation (https://github.com/constellation-app/constellation), a graph-focused analytical application, to enable threat intel analysts to efficiently and effectively enrich and pivot on data during their investigations.  
  
## Plugins  

### IPInfo  
  
  IPInfo.io is a service that provides accurate IP address data including geolocation, WHOIS information, and domains hosted. You can read more about IPInfo's Java implementation of their API at [their GitHub page](https://github.com/ipinfo/java).  

  This plugin will return geolocation and WHOIS information and add it to the IP node properties. It will also add any domains associated to the IP as a node graph node, with a relation to the original IP address node.  
  
### Shodan  
  Shodan.io is a search engine that allows you to search for information on internet-connected devices using various search filters. More information on the Shodan API can be found [here.](https://developer.shodan.io/api)  
  
  This plugin will return open ports and geolocation information and add them to the IP node properties. You can also choose to have the ports added to the graph as new related nodes, rather than as a node property.  

### ThreatCrowd
  ThreatCrowd is "a search engine for threats" run by AlienVault. 

  This plugin will allow you to search IPs and domains and return known associated domains, subdomains, email addresses, and file hashes. See the [ThreatCrowd API](https://github.com/AlienVault-OTX/ApiV2) documentation on GitHub for more information. 

## Setup  
  
  API keys for IPInfo and Shodan should be placed in ~/.config/constellation/constellation.conf:  
  ```
  $ cat ~/.config/constellation/constellation.conf 
  IPINFO_TOKEN = <token>
  SHODAN_TOKEN = <token>
  ```

## Building Constellation Threat Intel Tools

  If you would like to build Constellation Threat Intel Tools from source code, complete the following steps:
    
  1. Download Azul’s Zulu distribution of JDK 11 with JFX 11 for your operating system: [Windows 64-bit](https://cdn.azul.com/zulu/bin/zulu11.37.19-ca-fx-jdk11.0.6-win_x64.zip), [Linux 64-bit,](https://cdn.azul.com/zulu/bin/zulu11.37.19-ca-fx-jdk11.0.6-linux_x64.tar.gz) or [MacOS 64-bit](https://cdn.azul.com/zulu/bin/zulu11.37.19-ca-fx-jdk11.0.6-macosx_x64.tar.gz)

  2. Download [NetBeans 12](https://netbeans.apache.org/download/nb120/nb120.html)

  3. Update `netbeans_jdkhome` in netbeans.conf (Windows: `C:\Program Files\NetBeans-12\netbeans\etc`) to point to the Azul Zulu JDK you downloaded (Windows: `C:\Program Files\Azul\zulu11.37.19-ca-fx-jdk11.0.6-win_x64`)

  4. Clone this repository

  5. Clone the Constellation repository

  6. Open both the Threat Intel Tools and the Constellation module suites in NetBeans

  7. In the projects view, right-click `Threat Intel Tools -> Properties -> Libraries` and ensure all are unchecked except platform. Then click `Add project` and add Constellation. Then click `OK`

  8. In the Projects view, expand Threat Intel Tools `Important Files > Right-click 'Build Script' > 'update-dependencies-clean-build'`. This can take some time. 

  9. Start Constellation Threat Intel Tools by right-clicking on `Threat Intel Tools` and clicking `Run`.

## Feature Requests
  If you would like to see specific plugins or additional features, please create an Issue with your request. 
