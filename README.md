# Always Online: STUN servers
![GitHub commit activity](https://img.shields.io/github/commit-activity/w/pradt2/always-online-stun?style=for-the-badge)
![GitHub last commit](https://img.shields.io/github/last-commit/pradt2/always-online-stun?style=for-the-badge)
![GitHub](https://img.shields.io/github/license/pradt2/always-online-stun?style=for-the-badge)

Have you ever thought: *Gosh, why isn't there a regularly updated, comprehensive list of publicly available STUN servers*?

**Well, this is it. A list of online STUN servers, refreshed hourly.**

## How to use
Hardcode this link [valid_hosts.txt](https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_hosts.txt) into your application, and use it anytime you need a fresh list of online STUN servers.

Or, if you don't want to rely on DNS resolution, use [valid_ipv4s.txt](https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_ipv4s.txt) for IPv4, and [valid_ipv6s.txt](https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_ipv6s.txt) for IPv6 addresses.

### JS example with Geolocation

```javascript
const GEO_LOC_URL = "https://raw.githubusercontent.com/pradt2/always-online-stun/master/geoip_cache.txt";
const IPV4_URL = "https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_ipv4s.txt";
const GEO_USER_URL = "https://geolocation-db.com/json/";
const geoLocs = await(await fetch(GEO_LOC_URL)).json();
const { latitude, longitude } = await(await fetch(GEO_USER_URL)).json();
const closestAddr = (await(await fetch(IPV4_URL)).text()).trim().split('\n')
    .map(addr => {
        const [stunLat, stunLon] = geoLocs[addr.split(':')[0]];
        const dist = ((latitude - stunLat) ** 2 + (longitude - stunLon) ** 2 ) ** .5;
        return [addr, dist];
    }).reduce(([addrA, distA], [addrB, distB]) => distA <= distB ? [addrA, distA] : [addrB, distB])[0];
console.log(closestAddr); // prints the IP:PORT of the closest STUN server
```

## FAQ

### But hard-coding of links is baaaad?!
Well, not exactly. Hard-coding of links which were never meant to be hard-coded is bad.
Here the situation is different. Since I recommend that users hard-code the links to the few specific files, I'll avoid doing anything that would make the link invalid (e.g. I won't change the name of the file, name of the repository, my Github username, etc.).

### But I still don't feel comfortable hard-coding any links...
Feel free to open an issue and let's discuss your specific needs.

### How often are the lists refreshed?
Hourly, you can see the timestamp of the last check in the commit message.

### What RFC specs do the servers conform to? 

The `valid_nat_testing_*` lists contain servers that should be capable of both NAT detection and behaviour testing. These capabilities
roughly correspond to RFC5780 (and, implicitly, to RFC5389).

To qualify for these lists, a server has to correctly respond to a RFC5389 `BINDING` request and provide the `OTHER-ADDRESS` attribute in the response.
The presence of the `OTHER-ADDRESS` attribute is the spec-compliant way to advertise that a STUN server can be used for NAT behaviour tests.

_At the moment, no actual verification of the NAT behaviour testing capabilities is carried out. 
We rely on the STUN server maintainers to set the `OTHER-ADDRESS` attribute only if their server supports NAT behaviour testing.
If that's a problem for you (i.e. you need a stronger guarantee), please open an issue._

The other `valid_*` lists contain servers that are capable of NAT detection only. These are much bigger lists as only a small fraction 
of servers is configured to provide the full NAT testing capabilities.

To qualify for these lists, a server has to correctly respond to a RFC5389 `BINDING` request.

### What IP versions and transport protocols are tested?
IP versions 4 and 6. UDP and TCP.

### I noticed that the lists are shuffled on each check. Why?
Lazy/inconsiderate devs will tend to just grab the top-most link from the list (and TBF, can we blame them?).
By shuffling the list, I ensure that we don't end up spamming the same host forever.

### What servers are checked, and how can I add more publicly available servers?
The list is in `candidates.txt`. Feel free to create a PR adding more servers, or just open an issue and list them there.

### My server is on your list, and I don't like it. What can I do?
Open an issue, and it will be removed from the automated checks within 24 hours.

