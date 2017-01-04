# Sample sqlite database

# Create tables
sqlite3 example.db "create table hosts (host_id int, hostname text, scan_id int)"
sqlite3 example.db "create table vulnerabilities \
  (scan_id int, host_id int, severity int, name text, plugin int)"

# One more table, maybe not very useful:
sqlite3 example.db "create table os (fqdn text, ip text, netbios text, os text, mac text)"

# Sample queries

# Top 10 critical vulnerabilities
sqlite3 example.db "select count(*), name from vulnerabilities where severity=4 group by plugin order by count(*) desc limit 10"

# Top 10 hosts by number of vulnerabilities
sqlite3 example.db "select count(*), hosts.hostname, vulnerabilities.host_id from hosts, vulnerabilities where hosts.host_id=vulnerabilities.host_id and hosts.scan_id=vulnerabilities.scan_id group by vulnerabilities.host_id, vulnerabilities.scan_id order by count(*) desc limit 10"

# Top 10 hosts with critical vulnerabilities
sqlite3 example.db "select count(*), hosts.hostname, vulnerabilities.host_id from hosts, vulnerabilities where hosts.host_id=vulnerabilities.host_id and hosts.scan_id=vulnerabilities.scan_id and severity=4 group by vulnerabilities.host_id, vulnerabilities.scan_id order by count(*) desc limit 10"

# List vulnerabilities for a particular host
sqlite3 example.db "select v.severity, v.name from vulnerabilities as v, hosts as h where h.host_id=v.host_id and v.scan_id=h.scan_id and v.severity>0 and h.hostname='hostname.domain' group by v.plugin order by severity desc"

# List all critical vulnerabilities
sqlite3 example.db "select distinct plugin, name from vulnerabilities where severity=4"

# Find hosts with a vulnerability (example: Dirty COW)
sqlite3 example.db "select h.hostname, v.name from vulnerabilities as v, hosts as h where h.host_id=v.host_id and v.scan_id=h.scan_id and plugin in(94431,94254,94292,94409)"

# (example: Flash)
sqlite3 example.db "select h.hostname, v.name from vulnerabilities as v, hosts as h where h.host_id=v.host_id and v.scan_id=h.scan_id and name like '%flash%'"

