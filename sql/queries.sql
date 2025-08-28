-- Cybersecurity Web Threat Analysis - SQL Queries
-- =====================================================
-- 
-- This file contains SQL queries for analyzing cybersecurity threat data
-- stored in SQLite database for advanced reporting and analysis.

-- 1. Basic Threat Statistics
-- Get overall threat statistics for the current month
SELECT 
    COUNT(*) as total_connections,
    SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as suspicious_connections,
    ROUND(AVG(bytes_in), 2) as avg_bytes_in,
    ROUND(AVG(bytes_out), 2) as avg_bytes_out,
    COUNT(DISTINCT src_country) as unique_countries,
    COUNT(DISTINCT protocol) as unique_protocols
FROM threats 
WHERE timestamp >= date('now', 'start of month');

-- 2. Top Threat Countries
-- Identify countries with highest suspicious activity
SELECT 
    src_country,
    COUNT(*) as total_connections,
    SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as suspicious_connections,
    ROUND(
        (SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) * 100.0 / COUNT(*)), 2
    ) as threat_percentage,
    SUM(bytes_in + bytes_out) as total_bytes,
    ROUND(AVG(anomaly_score), 3) as avg_anomaly_score
FROM threats 
GROUP BY src_country
HAVING COUNT(*) >= 10
ORDER BY threat_percentage DESC, suspicious_connections DESC
LIMIT 20;

-- 3. Protocol Risk Analysis
-- Analyze threats by protocol type
SELECT 
    protocol,
    COUNT(*) as total_connections,
    SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as threats,
    ROUND(
        (SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) * 100.0 / COUNT(*)), 2
    ) as risk_percentage,
    AVG(bytes_in) as avg_bytes_in,
    AVG(bytes_out) as avg_bytes_out
FROM threats 
GROUP BY protocol
ORDER BY risk_percentage DESC, threats DESC;

-- 4. Port-based Security Analysis
-- Identify high-risk destination ports
SELECT 
    dst_port,
    COUNT(*) as connection_count,
    SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as threat_count,
    ROUND(
        (SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) * 100.0 / COUNT(*)), 2
    ) as threat_rate,
    SUM(bytes_in + bytes_out) as total_traffic,
    CASE 
        WHEN dst_port IN (22, 23, 53, 80, 135, 139, 443, 445, 993, 995) THEN 'High Risk'
        WHEN dst_port IN (21, 25, 110, 143, 465, 587, 993, 995) THEN 'Medium Risk'
        ELSE 'Low Risk'
    END as risk_category
FROM threats 
GROUP BY dst_port
HAVING COUNT(*) >= 5
ORDER BY threat_rate DESC, connection_count DESC
LIMIT 25;

-- 5. Time-based Threat Analysis
-- Analyze threat patterns by hour of day
SELECT 
    strftime('%H', timestamp) as hour_of_day,
    COUNT(*) as total_connections,
    SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as threats,
    ROUND(AVG(bytes_in + bytes_out), 2) as avg_traffic_volume
FROM threats 
WHERE timestamp >= date('now', '-7 days')
GROUP BY strftime('%H', timestamp)
ORDER BY hour_of_day;

-- 6. Daily Threat Trend
-- Get daily threat statistics for the last 30 days
SELECT 
    DATE(timestamp) as date,
    COUNT(*) as total_connections,
    SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as suspicious_connections,
    ROUND(
        (SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) * 100.0 / COUNT(*)), 2
    ) as threat_percentage,
    SUM(bytes_in + bytes_out) as total_bytes,
    COUNT(DISTINCT src_country) as unique_countries
FROM threats 
WHERE timestamp >= date('now', '-30 days')
GROUP BY DATE(timestamp)
ORDER BY date DESC;

-- 7. Anomaly Score Distribution
-- Analyze the distribution of anomaly scores
SELECT 
    CASE 
        WHEN anomaly_score >= 0.5 THEN 'Very High Risk'
        WHEN anomaly_score >= 0.2 THEN 'High Risk'
        WHEN anomaly_score >= 0.0 THEN 'Medium Risk'
        WHEN anomaly_score >= -0.2 THEN 'Low Risk'
        ELSE 'Very Low Risk'
    END as risk_level,
    COUNT(*) as connection_count,
    ROUND(AVG(bytes_in + bytes_out), 2) as avg_traffic,
    COUNT(DISTINCT src_country) as countries
FROM threats 
GROUP BY 
    CASE 
        WHEN anomaly_score >= 0.5 THEN 'Very High Risk'
        WHEN anomaly_score >= 0.2 THEN 'High Risk'
        WHEN anomaly_score >= 0.0 THEN 'Medium Risk'
        WHEN anomaly_score >= -0.2 THEN 'Low Risk'
        ELSE 'Very Low Risk'
    END
ORDER BY 
    CASE risk_level
        WHEN 'Very High Risk' THEN 1
        WHEN 'High Risk' THEN 2
        WHEN 'Medium Risk' THEN 3
        WHEN 'Low Risk' THEN 4
        ELSE 5
    END;

-- 8. Geographic Threat Concentration
-- Find countries with concentrated threat activities
SELECT 
    src_country,
    COUNT(DISTINCT src_ip) as unique_ips,
    COUNT(*) as total_connections,
    ROUND(COUNT(*) * 1.0 / COUNT(DISTINCT src_ip), 2) as connections_per_ip,
    SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as threats,
    ROUND(AVG(anomaly_score), 3) as avg_anomaly_score
FROM threats 
GROUP BY src_country
HAVING COUNT(DISTINCT src_ip) >= 3
ORDER BY connections_per_ip DESC, threats DESC
LIMIT 15;

-- 9. Traffic Volume Analysis
-- Analyze connections by traffic volume categories
SELECT 
    CASE 
        WHEN (bytes_in + bytes_out) >= 1000000 THEN 'Very High Volume'
        WHEN (bytes_in + bytes_out) >= 100000 THEN 'High Volume'
        WHEN (bytes_in + bytes_out) >= 10000 THEN 'Medium Volume'
        WHEN (bytes_in + bytes_out) >= 1000 THEN 'Low Volume'
        ELSE 'Very Low Volume'
    END as traffic_category,
    COUNT(*) as connection_count,
    SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as threats,
    ROUND(
        (SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) * 100.0 / COUNT(*)), 2
    ) as threat_rate,
    ROUND(AVG(bytes_in + bytes_out), 2) as avg_traffic_volume
FROM threats 
GROUP BY 
    CASE 
        WHEN (bytes_in + bytes_out) >= 1000000 THEN 'Very High Volume'
        WHEN (bytes_in + bytes_out) >= 100000 THEN 'High Volume'
        WHEN (bytes_in + bytes_out) >= 10000 THEN 'Medium Volume'
        WHEN (bytes_in + bytes_out) >= 1000 THEN 'Low Volume'
        ELSE 'Very Low Volume'
    END
ORDER BY avg_traffic_volume DESC;

-- 10. Suspicious IP Investigation
-- Deep dive into most suspicious IP addresses
SELECT 
    src_ip,
    src_country,
    COUNT(*) as total_connections,
    SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as suspicious_connections,
    ROUND(
        (SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) * 100.0 / COUNT(*)), 2
    ) as threat_rate,
    COUNT(DISTINCT dst_port) as unique_ports_accessed,
    COUNT(DISTINCT protocol) as unique_protocols,
    SUM(bytes_in + bytes_out) as total_traffic,
    ROUND(AVG(anomaly_score), 3) as avg_anomaly_score,
    MIN(timestamp) as first_seen,
    MAX(timestamp) as last_seen
FROM threats 
GROUP BY src_ip, src_country
HAVING SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) >= 3
ORDER BY threat_rate DESC, suspicious_connections DESC
LIMIT 20;

-- 11. Port Scanning Detection
-- Identify potential port scanning activities
SELECT 
    src_ip,
    src_country,
    COUNT(DISTINCT dst_port) as unique_ports_accessed,
    COUNT(*) as total_attempts,
    ROUND(AVG(bytes_in + bytes_out), 2) as avg_traffic_per_attempt,
    GROUP_CONCAT(DISTINCT dst_port ORDER BY dst_port) as ports_accessed,
    MIN(timestamp) as scan_start,
    MAX(timestamp) as scan_end,
    ROUND(
        (julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 24 * 60, 2
    ) as scan_duration_minutes
FROM threats 
GROUP BY src_ip, src_country
HAVING COUNT(DISTINCT dst_port) >= 5 
   AND COUNT(*) >= 10
   AND avg_traffic_per_attempt < 1000
ORDER BY unique_ports_accessed DESC, total_attempts DESC
LIMIT 15;

-- 12. Protocol Transition Analysis
-- Analyze connections that switch protocols
WITH protocol_switches AS (
    SELECT 
        src_ip,
        COUNT(DISTINCT protocol) as protocols_used,
        GROUP_CONCAT(DISTINCT protocol) as protocol_list,
        COUNT(*) as total_connections,
        SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as threats
    FROM threats 
    GROUP BY src_ip
    HAVING COUNT(DISTINCT protocol) > 1
)
SELECT 
    protocol_list,
    COUNT(*) as ips_with_pattern,
    SUM(total_connections) as total_connections,
    SUM(threats) as total_threats,
    ROUND(AVG(protocols_used), 1) as avg_protocols_per_ip
FROM protocol_switches
GROUP BY protocol_list
ORDER BY total_threats DESC, ips_with_pattern DESC
LIMIT 10;

-- 13. Weekly Threat Summary Report
-- Generate weekly summary for executive reporting
SELECT 
    'Current Week' as period,
    COUNT(*) as total_connections,
    SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as threats,
    ROUND(
        (SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) * 100.0 / COUNT(*)), 2
    ) as threat_percentage,
    COUNT(DISTINCT src_country) as countries_involved,
    COUNT(DISTINCT dst_port) as ports_targeted,
    ROUND(SUM(bytes_in + bytes_out) / 1024.0 / 1024.0 / 1024.0, 2) as total_gb_transferred,
    (SELECT src_country FROM threats 
     WHERE timestamp >= date('now', '-7 days') 
       AND threat_level = 'Suspicious' 
     GROUP BY src_country 
     ORDER BY COUNT(*) DESC 
     LIMIT 1) as top_threat_country
FROM threats 
WHERE timestamp >= date('now', '-7 days')

UNION ALL

SELECT 
    'Previous Week' as period,
    COUNT(*) as total_connections,
    SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as threats,
    ROUND(
        (SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) * 100.0 / COUNT(*)), 2
    ) as threat_percentage,
    COUNT(DISTINCT src_country) as countries_involved,
    COUNT(DISTINCT dst_port) as ports_targeted,
    ROUND(SUM(bytes_in + bytes_out) / 1024.0 / 1024.0 / 1024.0, 2) as total_gb_transferred,
    (SELECT src_country FROM threats 
     WHERE timestamp >= date('now', '-14 days') 
       AND timestamp < date('now', '-7 days')
       AND threat_level = 'Suspicious' 
     GROUP BY src_country 
     ORDER BY COUNT(*) DESC 
     LIMIT 1) as top_threat_country
FROM threats 
WHERE timestamp >= date('now', '-14 days') 
  AND timestamp < date('now', '-7 days');

-- 14. Create Indexes for Performance
-- Add indexes to improve query performance
CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
CREATE INDEX IF NOT EXISTS idx_threats_country ON threats(src_country);
CREATE INDEX IF NOT EXISTS idx_threats_level ON threats(threat_level);
CREATE INDEX IF NOT EXISTS idx_threats_port ON threats(dst_port);
CREATE INDEX IF NOT EXISTS idx_threats_protocol ON threats(protocol);
CREATE INDEX IF NOT EXISTS idx_threats_anomaly_score ON threats(anomaly_score);
CREATE INDEX IF NOT EXISTS idx_threats_composite ON threats(timestamp, threat_level, src_country);

-- 15. Database Maintenance Queries
-- Clean up old records (keep last 90 days)
-- DELETE FROM threats WHERE timestamp < date('now', '-90 days');

-- Update daily statistics
-- INSERT OR REPLACE INTO daily_stats (date, total_connections, suspicious_connections, top_country, avg_bytes_in, avg_bytes_out)
-- SELECT 
--     DATE(timestamp) as date,
--     COUNT(*) as total_connections,
--     SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as suspicious_connections,
--     (SELECT src_country FROM threats t2 
--      WHERE DATE(t2.timestamp) = DATE(threats.timestamp) 
--      GROUP BY src_country 
--      ORDER BY COUNT(*) DESC 
--      LIMIT 1) as top_country,
--     AVG(bytes_in) as avg_bytes_in,
--     AVG(bytes_out) as avg_bytes_out
-- FROM threats 
-- WHERE DATE(timestamp) = DATE('now', '-1 days')
-- GROUP BY DATE(timestamp);