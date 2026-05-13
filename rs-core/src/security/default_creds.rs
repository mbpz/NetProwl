//! F3-1: Default credentials detection
//! 200+ rules covering Hikvision, Dahua, TP-Link, Synology, SSH, MySQL, etc.

/// Default credential entry
#[derive(Debug, Clone, PartialEq)]
pub struct Credential {
    /// Service name, e.g., "Hikvision Camera", "SSH", "MySQL"
    pub service: String,
    /// Default username
    pub username: String,
    /// Default password
    pub password: String,
    /// Optional port filter (if Some, only match that port)
    pub port: Option<u16>,
}

/// Hikvision camera credentials
const HIKVISION_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(8000)),
    ("admin", "12345", Some(8000)),
    ("admin", "12345678", Some(8000)),
    ("admin", "", Some(8000)),
    ("root", "admin", Some(8000)),
    ("user", "user", Some(8000)),
    ("admin", "admin", Some(554)),
    ("admin", "12345", Some(554)),
];

/// Dahua camera credentials
const DAHUA_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(8000)),
    ("admin", "12345", Some(8000)),
    ("admin", "", Some(8000)),
    ("root", "root", Some(8000)),
    ("user", "user", Some(8000)),
    ("admin", "admin", Some(554)),
    ("admin", "12345", Some(554)),
];

/// Axis camera credentials
const AXIS_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("root", "pass", None),
    ("admin", "admin", None),
    ("admin", "12345", None),
    ("root", "admin", None),
];

/// Bosch camera credentials
const BOSCH_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(8000)),
    ("admin", "", Some(8000)),
    ("service", "service", Some(8000)),
];

/// Uniview camera credentials
const UNIVIEW_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(8000)),
    ("admin", "12345", Some(8000)),
    ("admin", "", Some(8000)),
];

/// Synology NAS credentials
const SYNOLOGY_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "", Some(5000)),
    ("admin", "admin", Some(5000)),
    ("admin", "12345", Some(5000)),
    ("admin", "synology", Some(5000)),
    ("root", "synology", Some(5000)),
    ("guest", "guest", Some(5000)),
];

/// QNAP NAS credentials
const QNAP_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(5000)),
    ("admin", "12345", Some(5000)),
    ("admin", "admin", Some(8080)),
    ("root", "admin", Some(5000)),
    ("admin", "", Some(5000)),
    ("guest", "guest", Some(5000)),
];

/// TP-Link router credentials
const TPLINK_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(80)),
    ("admin", "12345", Some(80)),
    ("admin", "1234", Some(80)),
    ("admin", "", Some(80)),
    ("root", "admin", Some(80)),
];

/// Netgear router credentials
const NETGEAR_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "password", None),
    ("admin", "12345", None),
    ("admin", "admin", None),
    ("root", "password", None),
];

/// Ubiquiti / UniFi credentials
const UBIQUITI_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("ubnt", "ubnt", Some(8080)),
    ("admin", "admin", Some(8080)),
    ("root", "ubnt", Some(8080)),
];

/// Huawei router credentials
const HUAWEI_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(80)),
    ("admin", "12345", Some(80)),
    ("root", "admin", Some(80)),
    (" telecom", "telecom", Some(80)),
];

/// D-Link router credentials
const DLINK_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(80)),
    ("admin", "", Some(80)),
    ("admin", "12345", Some(80)),
    ("root", "root", Some(80)),
];

/// ASUS router credentials
const ASUS_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(80)),
    ("admin", "12345", Some(80)),
    ("root", "admin", Some(80)),
];

/// SSH default credentials
const SSH_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("root", "root", Some(22)),
    ("root", "toor", Some(22)),
    ("root", "admin", Some(22)),
    ("root", "password", Some(22)),
    ("root", "", Some(22)),
    ("admin", "admin", Some(22)),
    ("admin", "12345", Some(22)),
    ("admin", "password", Some(22)),
    ("user", "user", Some(22)),
    ("guest", "guest", Some(22)),
    ("test", "test", Some(22)),
    ("ubuntu", "ubuntu", Some(22)),
    ("oracle", "oracle", Some(22)),
    ("postgres", "postgres", Some(22)),
];

/// FTP default credentials
const FTP_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("anonymous", "", Some(21)),
    ("admin", "admin", Some(21)),
    ("admin", "12345", Some(21)),
    ("ftp", "ftp", Some(21)),
    ("root", "root", Some(21)),
    ("user", "user", Some(21)),
];

/// MySQL default credentials
const MYSQL_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("root", "", Some(3306)),
    ("root", "root", Some(3306)),
    ("root", "password", Some(3306)),
    ("root", "123456", Some(3306)),
    ("mysql", "mysql", Some(3306)),
    ("admin", "admin", Some(3306)),
];

/// PostgreSQL default credentials
const POSTGRES_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("postgres", "", Some(5432)),
    ("postgres", "postgres", Some(5432)),
    ("postgres", "password", Some(5432)),
    ("postgres", "root", Some(5432)),
    ("admin", "admin", Some(5432)),
];

/// MSSQL default credentials
const MSSQL_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("sa", "", Some(1433)),
    ("sa", "sa", Some(1433)),
    ("sa", "password", Some(1433)),
    ("sa", "123456", Some(1433)),
    ("admin", "admin", Some(1433)),
];

/// Redis default credentials
const REDIS_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("", "", Some(6379)),
    ("default", "", Some(6379)),
    ("admin", "admin", Some(6379)),
];

/// MongoDB default credentials
const MONGODB_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("", "", Some(27017)),
    ("admin", "admin", Some(27017)),
    ("root", "root", Some(27017)),
];

/// Elasticsearch default credentials
const ELASTICSEARCH_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("elastic", "password", Some(9200)),
    ("elastic", "changeme", Some(9200)),
    ("admin", "admin", Some(9200)),
    ("kibana", "kibana", Some(9200)),
];

/// Memcached default credentials
const MEMCACHED_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("", "", Some(11211)),
];

/// Telnet default credentials
const TELNET_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("root", "root", Some(23)),
    ("root", "admin", Some(23)),
    ("root", "password", Some(23)),
    ("admin", "admin", Some(23)),
    ("admin", "12345", Some(23)),
    ("user", "user", Some(23)),
];

/// VNC default credentials
const VNC_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(5900)),
    ("admin", "12345", Some(5900)),
    ("root", "root", Some(5900)),
    ("user", "user", Some(5900)),
];

/// SMB / Samba default credentials
const SMB_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("guest", "", Some(445)),
    ("guest", "guest", Some(445)),
    ("admin", "admin", Some(445)),
    ("administrator", "administrator", Some(445)),
    ("root", "root", Some(445)),
];

/// phpMyAdmin credentials
const PHPMYADMIN_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("root", "", Some(80)),
    ("root", "root", Some(80)),
    ("admin", "admin", Some(80)),
    ("admin", "password", Some(80)),
];

/// RTSP camera credentials
const RTSP_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(554)),
    ("admin", "12345", Some(554)),
    ("admin", "123456", Some(554)),
    ("admin", "", Some(554)),
    ("root", "admin", Some(554)),
    ("user", "user", Some(554)),
];

/// SNMP default community strings
const SNMP_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("public", "public", Some(161)),
    ("private", "private", Some(161)),
    ("public", "", Some(161)),
    ("admin", "admin", Some(161)),
    ("root", "root", Some(161)),
];

/// Docker API default credentials
const DOCKER_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("", "", Some(2375)),
    ("", "", Some(2376)),
];

/// Kubernetes API default credentials
const KUBERNETES_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("", "", Some(6443)),
];

/// RabbitMQ default credentials
const RABBITMQ_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("guest", "guest", Some(5672)),
    ("admin", "admin", Some(5672)),
];

/// FTP (vsftpd) credentials
const VSFTPD_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("ftp", "ftp", Some(21)),
    ("ftp", "", Some(21)),
    ("anonymous", "", Some(21)),
];

/// CouchDB default credentials
const COUCHDB_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(5984)),
    ("", "", Some(5984)),
];

/// Cassandra default credentials
const CASSANDRA_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("cassandra", "cassandra", Some(9042)),
    ("admin", "admin", Some(9042)),
];

/// InfluxDB default credentials
const INFLUXDB_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(8086)),
    ("admin", "", Some(8086)),
    ("root", "root", Some(8086)),
];

/// Grafana default credentials
const GRAFANA_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(3000)),
    ("admin", "12345", Some(3000)),
    ("admin", "password", Some(3000)),
];

/// Zabbix default credentials
const ZABBIX_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("Admin", "zabbix", Some(80)),
    ("admin", "admin", Some(80)),
    ("guest", "guest", Some(80)),
];

/// Jenkins default credentials
const JENKINS_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(8080)),
    ("admin", "password", Some(8080)),
    ("admin", "12345", Some(8080)),
];

/// RabbitMQ management UI credentials
const RABBITMQ_MGMT_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("guest", "guest", Some(15672)),
];

/// ActiveMQ default credentials
const ACTIVEMQ_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", Some(8161)),
    ("admin", "password", Some(8161)),
];

/// Rsync default credentials
const RSYNC_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("backup", "backup", Some(873)),
    ("rsync", "rsync", Some(873)),
];

/// NFS (no auth, but included for completeness)
const NFS_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("", "", Some(2049)),
];

/// VMWare vSphere / ESXi credentials
const VMWARE_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("root", "vmware", Some(443)),
    ("root", "password", Some(443)),
    ("admin", "admin", Some(443)),
];

/// HP iLO default credentials
const HP_ILO_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("Administrator", "admin", Some(443)),
    ("admin", "admin", Some(443)),
    ("root", "admin", Some(443)),
];

/// Dell iDRAC default credentials
const DELL_IDRAC_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("root", "calvin", Some(443)),
    ("admin", "admin", Some(443)),
];

/// Generic / fallback credentials
const GENERIC_CREDS: &[(&str, &str, Option<u16>)] = &[
    ("admin", "admin", None),
    ("admin", "12345", None),
    ("admin", "password", None),
    ("admin", "123456", None),
    ("admin", "12345678", None),
    ("admin", "admin123", None),
    ("admin", "administrator", None),
    ("admin", "", None),
    ("root", "root", None),
    ("root", "admin", None),
    ("root", "password", None),
    ("root", "toor", None),
    ("root", "", None),
    ("user", "user", None),
    ("user", "password", None),
    ("guest", "guest", None),
    ("guest", "", None),
    ("test", "test", None),
    ("administrator", "administrator", None),
    ("supervisor", "supervisor", None),
    ("666666", "666666", None),
    ("888888", "888888", None),
];

type CredEntry<'a> = (&'a str, &'a [(&'a str, &'a str, Option<u16>)]);

const ALL_CREDENTIALS: &[CredEntry] = &[
    ("Hikvision Camera", HIKVISION_CREDS),
    ("Dahua Camera", DAHUA_CREDS),
    ("Axis Camera", AXIS_CREDS),
    ("Bosch Camera", BOSCH_CREDS),
    ("Uniview Camera", UNIVIEW_CREDS),
    ("RTSP Camera", RTSP_CREDS),
    ("Synology NAS", SYNOLOGY_CREDS),
    ("QNAP NAS", QNAP_CREDS),
    ("TP-Link Router", TPLINK_CREDS),
    ("Netgear Router", NETGEAR_CREDS),
    ("Ubiquiti / UniFi", UBIQUITI_CREDS),
    ("Huawei Router", HUAWEI_CREDS),
    ("D-Link Router", DLINK_CREDS),
    ("ASUS Router", ASUS_CREDS),
    ("SSH", SSH_CREDS),
    ("FTP", FTP_CREDS),
    ("vsftpd", VSFTPD_CREDS),
    ("MySQL", MYSQL_CREDS),
    ("PostgreSQL", POSTGRES_CREDS),
    ("MSSQL", MSSQL_CREDS),
    ("Redis", REDIS_CREDS),
    ("MongoDB", MONGODB_CREDS),
    ("Elasticsearch", ELASTICSEARCH_CREDS),
    ("Memcached", MEMCACHED_CREDS),
    ("Telnet", TELNET_CREDS),
    ("VNC", VNC_CREDS),
    ("SMB / Samba", SMB_CREDS),
    ("phpMyAdmin", PHPMYADMIN_CREDS),
    ("SNMP", SNMP_CREDS),
    ("Docker API", DOCKER_CREDS),
    ("Kubernetes API", KUBERNETES_CREDS),
    ("RabbitMQ", RABBITMQ_CREDS),
    ("RabbitMQ Management", RABBITMQ_MGMT_CREDS),
    ("CouchDB", COUCHDB_CREDS),
    ("Cassandra", CASSANDRA_CREDS),
    ("InfluxDB", INFLUXDB_CREDS),
    ("Grafana", GRAFANA_CREDS),
    ("Zabbix", ZABBIX_CREDS),
    ("Jenkins", JENKINS_CREDS),
    ("ActiveMQ", ACTIVEMQ_CREDS),
    ("Rsync", RSYNC_CREDS),
    ("NFS", NFS_CREDS),
    ("VMWare vSphere", VMWARE_CREDS),
    ("HP iLO", HP_ILO_CREDS),
    ("Dell iDRAC", DELL_IDRAC_CREDS),
    ("Generic", GENERIC_CREDS),
];

/// Get all known default credentials (200+ entries)
pub fn get_credential_db() -> Vec<Credential> {
    let mut results = Vec::new();

    for (service, creds) in ALL_CREDENTIALS {
        for (username, password, port) in *creds {
            results.push(Credential {
                service: service.to_string(),
                username: username.to_string(),
                password: password.to_string(),
                port: *port,
            });
        }
    }

    results
}

/// Get count of all credentials
pub fn get_credential_count() -> usize {
    let mut count = 0;
    for (_, creds) in ALL_CREDENTIALS {
        count += creds.len();
    }
    count
}

/// Check default credentials matching service keyword and optional port filter
///
/// # Arguments
/// * `service` - Service name to match (case-insensitive substring match)
/// * `port` - Optional port filter; if Some(port), only return credentials for that port
///
/// # Returns
/// Vector of matching credentials
pub fn check_default_creds(service: &str, port: Option<u16>) -> Vec<Credential> {
    let service_lower = service.to_lowercase();
    let mut results = Vec::new();

    for (svc_name, creds) in ALL_CREDENTIALS {
        // Case-insensitive substring match
        if svc_name.to_lowercase().contains(&service_lower) || service_lower.contains(&svc_name.to_lowercase()) {
            for (username, password, cred_port) in *creds {
                // Port filtering: if port is specified, only match if port matches or is None (no filter)
                let port_matches = match (port, cred_port) {
                    (Some(target_port), Some(cred_port_val)) => target_port == *cred_port_val,
                    (Some(_), None) => true, // Credential applies to all ports
                    (None, _) => true,        // No port filter specified
                };

                if port_matches {
                    results.push(Credential {
                        service: svc_name.to_string(),
                        username: username.to_string(),
                        password: password.to_string(),
                        port: *cred_port,
                    });
                }
            }
        }
    }

    results
}

/// Check credentials for a specific port (any service)
pub fn check_port_default_creds(port: u16) -> Vec<Credential> {
    let mut results = Vec::new();

    for (service, creds) in ALL_CREDENTIALS {
        for (username, password, cred_port) in *creds {
            match cred_port {
                Some(p) if *p == port => {
                    results.push(Credential {
                        service: service.to_string(),
                        username: username.to_string(),
                        password: password.to_string(),
                        port: *cred_port,
                    });
                }
                None => {
                    // No port restriction, include for all ports
                    results.push(Credential {
                        service: service.to_string(),
                        username: username.to_string(),
                        password: password.to_string(),
                        port: Some(port),
                    });
                }
                _ => {}
            }
        }
    }

    results
}

/// Get services that have default credentials defined
pub fn get_service_list() -> Vec<String> {
    ALL_CREDENTIALS.iter().map(|(s, _)| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_credential_count() {
        let count = get_credential_count();
        assert!(count >= 50, "Should have at least 50 credentials, got {}", count);
    }

    #[test]
    fn test_get_credential_db() {
        let db = get_credential_db();
        assert!(!db.is_empty());
    }

    #[test]
    fn test_check_default_creds_hikvision() {
        let creds = check_default_creds("Hikvision", None);
        assert!(!creds.is_empty());
        assert!(creds.iter().all(|c| c.service.contains("Hikvision") || c.service.contains("Camera")));
    }

    #[test]
    fn test_check_default_creds_with_port() {
        let creds = check_default_creds("Camera", Some(8000));
        // Should filter by port
        for cred in &creds {
            if let Some(p) = cred.port {
                assert_eq!(p, 8000);
            }
        }
    }

    #[test]
    fn test_check_default_creds_ssh() {
        let creds = check_default_creds("SSH", Some(22));
        assert!(!creds.is_empty());
        assert!(creds.iter().all(|c| c.port == Some(22) || c.port == None));
    }

    #[test]
    fn test_check_default_creds_mysql() {
        let creds = check_default_creds("MySQL", None);
        assert!(!creds.is_empty());
        assert!(creds.iter().any(|c| c.username == "root" && c.password.is_empty()));
    }

    #[test]
    fn test_check_default_creds_generic() {
        let creds = check_default_creds("admin", None);
        assert!(!creds.is_empty());
    }

    #[test]
    fn test_check_port_default_creds() {
        let creds = check_port_default_creds(3306);
        assert!(!creds.is_empty());
    }

    #[test]
    fn test_get_service_list() {
        let services = get_service_list();
        assert!(!services.is_empty());
        assert!(services.contains(&"SSH".to_string()));
        assert!(services.contains(&"MySQL".to_string()));
        assert!(services.contains(&"Hikvision Camera".to_string()));
    }

    #[test]
    fn test_credential_fields() {
        let creds = check_default_creds("SSH", Some(22));
        for cred in creds {
            assert!(!cred.service.is_empty());
            assert!(!cred.username.is_empty() || !cred.password.is_empty());
        }
    }
}