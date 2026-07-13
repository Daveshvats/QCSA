"""Offline Maven CVE database with OSV.dev integration — 35+ curated CVEs."""
from __future__ import annotations
import json, re, urllib.request, urllib.error
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Tuple

import logging
_logger = logging.getLogger(__name__.replace('loomscan.', ''))

@dataclass
class MavenCVE:
    cve_id: str; package: str; affected_versions: str; fixed_version: str
    severity: str; cwe: str; description: str; exploitability: str; fix_url: str = ""

BUNDLED_CVES = [
    MavenCVE("CVE-2022-22965","org.springframework:spring-beans","<5.3.18","5.3.18","critical","CWE-470","Spring4Shell RCE","exploitable"),
    MavenCVE("CVE-2022-22965","org.springframework:spring-webmvc","<5.3.18","5.3.18","critical","CWE-470","Spring4Shell (webmvc)","exploitable"),
    MavenCVE("CVE-2022-22950","org.springframework:spring-expression","<5.3.17","5.3.17","medium","CWE-770","Spring Expression DoS","present_not_exploitable"),
    MavenCVE("CVE-2022-42003","com.fasterxml.jackson.core:jackson-databind","<2.13.4.1","2.13.4.1","high","CWE-787","Jackson DoS nested arrays","exploitable"),
    MavenCVE("CVE-2022-42004","com.fasterxml.jackson.core:jackson-databind","<2.13.4.1","2.13.4.1","high","CWE-787","Jackson DoS deep nested","exploitable"),
    MavenCVE("CVE-2021-44228","org.apache.logging.log4j:log4j-core","2.0-2.14.1","2.15.0","critical","CWE-502","Log4Shell JNDI RCE","exploitable"),
    MavenCVE("CVE-2021-45046","org.apache.logging.log4j:log4j-core","2.0-2.15.0","2.16.0","critical","CWE-502","Log4j JNDI RCE (incomplete fix)","exploitable"),
    MavenCVE("CVE-2021-45105","org.apache.logging.log4j:log4j-core","2.0-2.16.0","2.17.0","high","CWE-400","Log4j DoS recursive lookup","exploitable"),
    MavenCVE("CVE-2021-44832","org.apache.logging.log4j:log4j-core","2.0-2.17.0","2.17.1","critical","CWE-502","Log4j JDBCAppender RCE","present_not_exploitable"),
    MavenCVE("CVE-2019-17571","org.apache.logging.log4j:log4j","1.2","none (EOL)","critical","CWE-502","Log4j 1.x SocketServer RCE","present_not_exploitable"),
    MavenCVE("CVE-2022-23305","org.apache.logging.log4j:log4j","1.2","none (EOL)","critical","CWE-89","Log4j 1.x JDBCAppender SQLi","present_not_exploitable"),
    MavenCVE("CVE-2022-23302","org.apache.logging.log4j:log4j","1.2","none (EOL)","critical","CWE-502","Log4j 1.x JMSAppender RCE","present_not_exploitable"),
    MavenCVE("CVE-2022-42889","org.apache.commons:commons-text","1.5-1.9","1.10.0","critical","CWE-94","Text4Shell StringSubstitutor RCE","exploitable"),
    MavenCVE("CVE-2024-47554","commons-io:commons-io","<2.13.0","2.13.0","medium","CWE-400","Commons IO XmlStreamReader DoS","present_not_exploitable"),
    MavenCVE("CVE-2015-7501","commons-collections:commons-collections","<3.2.2","3.2.2","critical","CWE-502","Commons Collections deserialization RCE","present_not_exploitable"),
    MavenCVE("CVE-2024-31033","io.jsonwebtoken:jjwt","<0.12.0","0.12.0","high","CWE-347","JJWT signature confusion","present_not_exploitable"),
    MavenCVE("CVE-2024-31033","io.jsonwebtoken:jjwt-api","<0.12.0","0.12.0","high","CWE-347","JJWT signature confusion (api)","present_not_exploitable"),
    MavenCVE("CVE-2022-31197","org.postgresql:postgresql","<42.4.1","42.4.1","high","CWE-89","PostgreSQL JDBC SQLi via getURL()","present_not_exploitable"),
    MavenCVE("CVE-2022-41946","org.postgresql:postgresql","<42.4.3","42.4.3","medium","CWE-200","PostgreSQL JDBC temp-file info disclosure","present_not_exploitable"),
    MavenCVE("CVE-2023-3635","com.squareup.okhttp3:okhttp","<4.12.0","4.12.0","high","CWE-400","OkHttp DoS multipart","present_not_exploitable"),
    MavenCVE("CVE-2022-36033","org.jsoup:jsoup","<1.15.3","1.15.3","medium","CWE-79","jsoup Cleaner XSS bypass","present_not_exploitable"),
    MavenCVE("CVE-2017-9096","com.itextpdf:itextpdf","<5.5.12","5.5.12","high","CWE-611","iText 5.x XXE","present_not_exploitable"),
    MavenCVE("CVE-2017-9096","com.itextpdf:itext7-core","<7.1.12","7.1.12","high","CWE-611","iText 7.x XXE","present_not_exploitable"),
    MavenCVE("CVE-2022-40152","com.fasterxml.woodstox:woodstox-core","<6.4.0","6.4.0","high","CWE-787","Woodstox XML OOB write","present_not_exploitable"),
    MavenCVE("CVE-2022-26336","org.apache.poi:poi","<5.2.3","5.2.3","medium","CWE-787","Apache POI DoS","present_not_exploitable"),
    MavenCVE("CVE-2022-26336","org.apache.poi:poi-ooxml","<5.2.3","5.2.3","medium","CWE-787","Apache POI OOXML DoS","present_not_exploitable"),
    MavenCVE("CVE-2023-44487","io.netty:netty-codec-http2","<4.1.100.Final","4.1.100.Final","high","CWE-400","HTTP/2 Rapid Reset DDoS","present_not_exploitable"),
    MavenCVE("CVE-2022-1471","org.yaml:snakeyaml","<2.0","2.0","critical","CWE-502","SnakeYAML deserialization RCE","present_not_exploitable"),
    MavenCVE("CVE-2022-42252","org.apache.tomcat.embed:tomcat-embed-core","<10.0.27","10.0.27","low","CWE-444","Tomcat request smuggling","present_not_exploitable"),
    MavenCVE("CVE-2019-14900","org.hibernate:hibernate-core","<5.4.24.Final","5.4.24.Final","high","CWE-89","Hibernate HQL injection","present_not_exploitable"),
    MavenCVE("CVE-2023-33201","org.bouncycastle:bcprov-jdk15on","<1.74","1.74","high","CWE-203","Bouncy Castle LDAP injection","present_not_exploitable"),
    MavenCVE("CVE-2020-10683","org.dom4j:dom4j","<2.1.3","2.1.3","critical","CWE-611","dom4j XXE","present_not_exploitable"),
    MavenCVE("CVE-2020-13956","org.apache.httpcomponents:httpclient","<4.5.13","4.5.13","medium","CWE-20","HttpClient URI parsing SSRF","present_not_exploitable"),
    # === Additional CVEs for comprehensive coverage ===
    # Spring Framework additional
    MavenCVE("CVE-2022-22965","org.springframework:spring-core","<5.3.18","5.3.18","critical","CWE-470","Spring4Shell (core)","exploitable"),
    MavenCVE("CVE-2022-22950","org.springframework:spring-core","<5.3.17","5.3.17","medium","CWE-770","Spring Expression DoS (core)","present_not_exploitable"),
    MavenCVE("CVE-2021-22118","org.springframework:spring-web","<5.3.8","5.3.8","high","CWE-126","Spring Web DoS","present_not_exploitable"),
    MavenCVE("CVE-2020-5421","org.springframework:spring-web","<5.2.16","5.2.16","medium","CWE-352","Spring Web CSRF","present_not_exploitable"),
    # Spring Boot
    MavenCVE("CVE-2022-22965","org.springframework.boot:spring-boot","<2.6.6","2.6.6","critical","CWE-470","Spring4Shell (boot)","exploitable"),
    # Jackson additional
    MavenCVE("CVE-2020-36518","com.fasterxml.jackson.core:jackson-databind","<2.13.0","2.13.0","high","CWE-787","Jackson DoS StackOverflow","exploitable"),
    MavenCVE("CVE-2019-12384","com.fasterxml.jackson.core:jackson-databind","<2.9.10.1","2.9.10.1","high","CWE-502","Jackson deserialization","present_not_exploitable"),
    MavenCVE("CVE-2018-7489","com.fasterxml.jackson.core:jackson-databind","<2.9.5","2.9.5","critical","CWE-502","Jackson deserialization RCE","present_not_exploitable"),
    MavenCVE("CVE-2017-7525","com.fasterxml.jackson.core:jackson-databind","<2.8.10","2.8.10","critical","CWE-502","Jackson deserialization RCE","present_not_exploitable"),
    # Log4j additional
    MavenCVE("CVE-2021-44228","org.apache.logging.log4j:log4j-to-slf4j","<2.16.0","2.16.0","high","CWE-502","Log4j-to-slf4j JNDI","present_not_exploitable"),
    # Apache Commons
    MavenCVE("CVE-2015-7501","commons-collections:commons-collections","<3.2.2","3.2.2","critical","CWE-502","Commons Collections RCE","present_not_exploitable"),
    MavenCVE("CVE-2015-7501","org.apache.commons:commons-collections4","<4.1","4.1","critical","CWE-502","Commons Collections4 RCE","present_not_exploitable"),
    MavenCVE("CVE-2022-42889","org.apache.commons:commons-text","1.5-1.9","1.10.0","critical","CWE-94","Text4Shell","exploitable"),
    MavenCVE("CVE-2021-37507","org.apache.commons:commons-configuration","<1.10","1.10","high","CWE-611","Commons Config XXE","present_not_exploitable"),
    # Tomcat
    MavenCVE("CVE-2023-46589","org.apache.tomcat.embed:tomcat-embed-core","<9.0.83","9.0.83","medium","CWE-444","Tomcat HTTP request smuggling","present_not_exploitable"),
    MavenCVE("CVE-2023-42794","org.apache.tomcat.embed:tomcat-embed-core","<9.0.81","9.0.81","low","CWE-400","Tomcat DoS","present_not_exploitable"),
    MavenCVE("CVE-2022-42252","org.apache.tomcat.embed:tomcat-embed-core","<10.0.27","10.0.27","low","CWE-444","Tomcat request smuggling","present_not_exploitable"),
    MavenCVE("CVE-2022-29885","org.apache.tomcat.embed:tomcat-embed-core","<10.0.21","10.0.21","medium","CWE-400","Tomcat EncryptInterceptor","present_not_exploitable"),
    # Hibernate
    MavenCVE("CVE-2019-14900","org.hibernate:hibernate-core","<5.4.24.Final","5.4.24.Final","high","CWE-89","Hibernate HQL injection","present_not_exploitable"),
    MavenCVE("CVE-2020-25638","org.hibernate:hibernate-core","<5.4.24.Final","5.4.24.Final","high","CWE-89","Hibernate SQL injection","present_not_exploitable"),
    # Netty
    MavenCVE("CVE-2023-44487","io.netty:netty-codec-http2","<4.1.100.Final","4.1.100.Final","high","CWE-400","HTTP/2 Rapid Reset","present_not_exploitable"),
    MavenCVE("CVE-2023-34462","io.netty:netty-common","<4.1.94.Final","4.1.94.Final","medium","CWE-400","Netty DoS SslHandler","present_not_exploitable"),
    MavenCVE("CVE-2022-24823","io.netty:netty-common","<4.1.86.Final","4.1.86.Final","medium","CWE-400","Netty TempFile DoS","present_not_exploitable"),
    # JJWT
    MavenCVE("CVE-2024-31033","io.jsonwebtoken:jjwt","<0.12.0","0.12.0","high","CWE-347","JJWT signature confusion","present_not_exploitable"),
    MavenCVE("CVE-2024-31033","io.jsonwebtoken:jjwt-impl","<0.12.0","0.12.0","high","CWE-347","JJWT signature confusion (impl)","present_not_exploitable"),
    MavenCVE("CVE-2024-31033","io.jsonwebtoken:jjwt-jackson","<0.12.0","0.12.0","high","CWE-347","JJWT signature confusion (jackson)","present_not_exploitable"),
    # SnakeYAML
    MavenCVE("CVE-2022-1471","org.yaml:snakeyaml","<2.0","2.0","critical","CWE-502","SnakeYAML RCE Constructor","present_not_exploitable"),
    MavenCVE("CVE-2022-38751","org.yaml:snakeyaml","<1.32","1.32","high","CWE-787","SnakeYAML DoS","present_not_exploitable"),
    MavenCVE("CVE-2022-38752","org.yaml:snakeyaml","<1.32","1.32","high","CWE-787","SnakeYAML DoS","present_not_exploitable"),
    # dom4j
    MavenCVE("CVE-2020-10683","org.dom4j:dom4j","<2.1.3","2.1.3","critical","CWE-611","dom4j XXE","present_not_exploitable"),
    # Bouncy Castle
    MavenCVE("CVE-2023-33201","org.bouncycastle:bcprov-jdk15on","<1.74","1.74","high","CWE-203","Bouncy Castle LDAP injection","present_not_exploitable"),
    MavenCVE("CVE-2023-33201","org.bouncycastle:bcprov-jdk18on","<1.74","1.74","high","CWE-203","Bouncy Castle LDAP injection (jdk18)","present_not_exploitable"),
    MavenCVE("CVE-2024-29857","org.bouncycastle:bcprov-jdk18on","<1.78","1.78","medium","CWE-400","Bouncy Castle DoS","present_not_exploitable"),
    # Apache POI
    MavenCVE("CVE-2022-26336","org.apache.poi:poi","<5.2.3","5.2.3","medium","CWE-787","Apache POI DoS","present_not_exploitable"),
    MavenCVE("CVE-2022-26336","org.apache.poi:poi-ooxml","<5.2.3","5.2.3","medium","CWE-787","Apache POI OOXML DoS","present_not_exploitable"),
    MavenCVE("CVE-2019-12415","org.apache.poi:poi","<4.1.1","4.1.1","medium","CWE-611","Apache POI XXE","present_not_exploitable"),
    # PostgreSQL JDBC
    MavenCVE("CVE-2022-31197","org.postgresql:postgresql","<42.4.1","42.4.1","high","CWE-89","PostgreSQL JDBC SQLi","present_not_exploitable"),
    MavenCVE("CVE-2022-41946","org.postgresql:postgresql","<42.4.3","42.4.3","medium","CWE-200","PostgreSQL JDBC info disclosure","present_not_exploitable"),
    MavenCVE("CVE-2024-1597","org.postgresql:postgresql","<42.7.2","42.7.2","critical","CWE-89","PostgreSQL JDBC SQLi (PreparedStatement)","exploitable"),
    # OkHttp
    MavenCVE("CVE-2023-3635","com.squareup.okhttp3:okhttp","<4.12.0","4.12.0","high","CWE-400","OkHttp DoS multipart","present_not_exploitable"),
    # jsoup
    MavenCVE("CVE-2022-36033","org.jsoup:jsoup","<1.15.3","1.15.3","medium","CWE-79","jsoup Cleaner XSS bypass","present_not_exploitable"),
    # iText
    MavenCVE("CVE-2017-9096","com.itextpdf:itextpdf","<5.5.12","5.5.12","high","CWE-611","iText 5.x XXE","present_not_exploitable"),
    MavenCVE("CVE-2017-9096","com.itextpdf:itext7-core","<7.1.12","7.1.12","high","CWE-611","iText 7.x XXE","present_not_exploitable"),
    # Woodstox
    MavenCVE("CVE-2022-40152","com.fasterxml.woodstox:woodstox-core","<6.4.0","6.4.0","high","CWE-787","Woodstox XML OOB write","present_not_exploitable"),
    # Apache HTTP Components
    MavenCVE("CVE-2020-13956","org.apache.httpcomponents:httpclient","<4.5.13","4.5.13","medium","CWE-20","HttpClient SSRF","present_not_exploitable"),
    MavenCVE("CVE-2023-37256","org.apache.httpcomponents:httpclient","<4.5.14","4.5.14","medium","CWE-113","HttpClient response splitting","present_not_exploitable"),
    # Gson
    MavenCVE("CVE-2022-25647","com.google.code.gson:gson","<2.8.9","2.8.9","medium","CWE-502","Gson deserialization DoS","present_not_exploitable"),
    # xerces
    MavenCVE("CVE-2022-23437","xerces:xercesImpl","<2.12.2","2.12.2","medium","CWE-611","Xerces XXE","present_not_exploitable"),
    # Apache CXF
    MavenCVE("CVE-2022-46364","org.apache.cxf:cxf-core","<3.5.5","3.5.5","critical","CWE-502","CXF SSRF","present_not_exploitable"),
    # Struts
    MavenCVE("CVE-2023-50164","org.apache.struts:struts2-core","<2.5.33","2.5.33","critical","CWE-918","Struts2 file upload RCE","exploitable"),
    MavenCVE("CVE-2017-5638","org.apache.struts:struts2-core","<2.3.32","2.3.32","critical","CWE-94","Struts2 RCE (Content-Type)","present_not_exploitable"),
    # Shiro
    MavenCVE("CVE-2022-32532","org.apache.shiro:shiro-core","<1.9.1","1.9.1","high","CWE-287","Shiro auth bypass","present_not_exploitable"),
    MavenCVE("CVE-2020-17523","org.apache.shiro:shiro-core","<1.7.0","1.7.0","critical","CWE-287","Shiro auth bypass (whitespace)","present_not_exploitable"),
    # Spring Security
    MavenCVE("CVE-2022-22978","org.springframework.security:spring-security-core","<5.6.5","5.6.5","medium","CWE-863","Spring Security RegexRequestMatcher bypass","present_not_exploitable"),
    # Velocity
    MavenCVE("2020-13936","org.apache.velocity:velocity-engine-core","<2.3","2.3","critical","CWE-94","Velocity RCE","present_not_exploitable"),
    # Thymeleaf
    MavenCVE("CVE-2023-38286","org.thymeleaf:thymeleaf","<3.1.2.RELEASE","3.1.2.RELEASE","medium","CWE-1333","Thymeleaf SSTI","present_not_exploitable"),
    # Lombok (not a CVE but security concern)
    MavenCVE("CVE-2021-42550","ch.qos.logback:logback-classic","<1.2.9","1.2.9","high","CWE-94","Logback JNDI RCE","present_not_exploitable"),
]

SPRING_BOOT_BOM_VERSIONS = {
    "2.6.4": {"org.springframework:spring-beans":"5.3.16","org.springframework:spring-webmvc":"5.3.16",
              "org.springframework:spring-expression":"5.3.16","com.fasterxml.jackson.core:jackson-databind":"2.13.2",
              "org.apache.tomcat.embed:tomcat-embed-core":"9.0.60","org.yaml:snakeyaml":"1.29",
              "org.hibernate:hibernate-core":"5.6.5.Final"},
    "2.6.6": {"org.springframework:spring-beans":"5.3.18","org.springframework:spring-webmvc":"5.3.18"},
    "2.7.0": {"org.springframework:spring-beans":"5.3.20","com.fasterxml.jackson.core:jackson-databind":"2.13.3"},
    "2.7.18": {"org.springframework:spring-beans":"5.3.31","com.fasterxml.jackson.core:jackson-databind":"2.13.5"},
}

def parse_maven_version(version):
    version = re.sub(r'[-.].*(?:Final|RELEASE|redhat|SP|GA|Beta|CR|RC|M|alpha|beta).*','',version,flags=re.IGNORECASE)
    version = version.split('.')[0:4]
    parsed = []
    for part in version:
        m = re.match(r'(\d+)', part)
        parsed.append(int(m.group(1)) if m else 0)
    return tuple(parsed)

def is_version_affected(version, affected_range):
    vt = parse_maven_version(version)
    ar = affected_range.strip()
    if ar.startswith("<") and not ar.startswith("<="):
        return vt < parse_maven_version(ar[1:])
    if ar.startswith("<="):
        return vt <= parse_maven_version(ar[2:])
    if "-" in ar:
        parts = ar.split("-")
        if len(parts)==2:
            return parse_maven_version(parts[0]) <= vt <= parse_maven_version(parts[1])
    return vt == parse_maven_version(ar)

class MavenCVEDatabase:
    def __init__(self, cache_dir=None):
        self.cache_dir = cache_dir or Path.home()/".loomscan-cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_file = self.cache_dir/"maven_cves.json"
        self.cves = list(BUNDLED_CVES)
        self._load_cache()
    def _load_cache(self):
        if self.db_file.exists():
            try:
                data = json.loads(self.db_file.read_text())
                cached = [MavenCVE(**c) for c in data.get("cves",[])]
                bundled_keys = {(c.cve_id,c.package) for c in self.cves}
                self.cves += [c for c in cached if (c.cve_id,c.package) not in bundled_keys]
            except Exception: pass  # v4.5: suppressed — add logging
    def _save_cache(self):
        self.db_file.write_text(json.dumps({"cves":[asdict(c) for c in self.cves]}, indent=2))
    def update_from_osv(self, packages=None):
        if packages is None: packages = list({c.package for c in self.cves})
        new_count = 0
        for pkg in packages:
            try:
                req = urllib.request.Request("https://api.osv.dev/v1/query",
                    data=json.dumps({"package":{"ecosystem":"Maven","name":pkg}}).encode(),
                    headers={"Content-Type":"application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                for vuln in data.get("vulns",[]):
                    cve_id = vuln.get("id","")
                    if any(c.cve_id==cve_id and c.package==pkg for c in self.cves): continue
                    severity = "medium"
                    for sev in vuln.get("severity",[]):
                        if sev.get("type")=="CVSS_V3":
                            s = sev.get("score","")
                            if "AV:N" in s and "AC:L" in s: severity = "critical" if "C:H" in s else "high"
                            elif "AV:N" in s: severity = "high"
                    ar = ""; fv = ""
                    for aff in vuln.get("affected",[]):
                        if aff.get("package",{}).get("name")==pkg:
                            for rng in aff.get("ranges",[]):
                                for ev in rng.get("events",[]):
                                    if "introduced" in ev: ar = f">={ev['introduced']}"
                                    if "fixed" in ev:
                                        fv = ev["fixed"]
                                        ar = f"<{fv}" if not ar else f"{ar}-{fv}"
                    if not ar and not fv: continue
                    self.cves.append(MavenCVE(cve_id,pkg,ar or f"<{fv}",fv or "unknown",severity,"CWE-Other",
                        vuln.get("summary","OSV.dev")[:200],"present_not_exploitable"))
                    new_count += 1
            except: continue
        if new_count>0: self._save_cache()
        return new_count
    def lookup(self, package, version):
        return [c for c in self.cves if c.package.lower()==package.lower() and is_version_affected(version,c.affected_versions)]
    def stats(self):
        return {"total_cves":len(self.cves),"unique_packages":len({c.package for c in self.cves}),
                "by_severity":{s:sum(1 for c in self.cves if c.severity==s) for s in ["critical","high","medium","low"]}}

def scan_pom_xml_for_cves(pom_path, cve_db=None):
    if cve_db is None: cve_db = MavenCVEDatabase()
    try: content = pom_path.read_text(encoding="utf-8")
    except: return []
    findings = []
    spring_boot_version = None
    m = re.search(r'<parent>\s*<groupId>org\.springframework\.boot</groupId>\s*<artifactId>spring-boot-starter-parent</artifactId>\s*<version>([^<]+)</version>', content)
    if m: spring_boot_version = m.group(1).strip()
    bom_versions = SPRING_BOOT_BOM_VERSIONS.get(spring_boot_version,{}) if spring_boot_version else {}
    for dep in re.finditer(r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?', content):
        gid, aid = dep.group(1).strip(), dep.group(2).strip()
        version = dep.group(3)
        if version: version = version.strip().lstrip("${").rstrip("}")
        package = f"{gid}:{aid}"
        if not version and package in bom_versions: version = bom_versions[package]
        if not version: continue
        if version.startswith("${"):
            prop = version[2:-1]
            pm = re.search(rf'<{prop}>([^<]+)</{prop}>', content)
            if pm: version = pm.group(1).strip()
            else: continue
        for cve in cve_db.lookup(package, version):
            findings.append({"cve_id":cve.cve_id,"package":package,"version":version,"severity":cve.severity,
                "cwe":cve.cwe,"description":cve.description,"affected_versions":cve.affected_versions,
                "fixed_version":cve.fixed_version,"exploitability":cve.exploitability,"fix_url":cve.fix_url,
                "fix":f"Upgrade {package} from {version} to {cve.fixed_version}+","source":"pom.xml"})
    for package, version in bom_versions.items():
        if any(f["package"]==package for f in findings): continue
        for cve in cve_db.lookup(package, version):
            findings.append({"cve_id":cve.cve_id,"package":package,"version":version,"severity":cve.severity,
                "cwe":cve.cwe,"description":cve.description,"affected_versions":cve.affected_versions,
                "fixed_version":cve.fixed_version,"exploitability":cve.exploitability,"fix_url":cve.fix_url,
                "fix":f"Upgrade {package} (Spring Boot {spring_boot_version} BOM) from {version} to {cve.fixed_version}+",
                "source":f"Spring Boot {spring_boot_version} BOM (transitive)"})
    return findings
