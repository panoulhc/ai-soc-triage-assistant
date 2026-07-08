from app.ioc_extractor import extract_iocs


def test_extract_public_and_private_ips():
    alert = {
        "source_ip": "185.220.101.45",
        "internal_ip": "192.168.1.10",
    }

    iocs = extract_iocs(alert)

    assert "185.220.101.45" in iocs.public_ip_addresses
    assert "192.168.1.10" in iocs.private_ip_addresses


def test_extract_url_domain_email_and_hash():
    alert = {
        "url": "http://fake-login-example.com/reset",
        "email": "user@example.com",
        "hash": "44d88612fea8a8f36de82e1278abb02f",
    }

    iocs = extract_iocs(alert)

    assert "http://fake-login-example.com/reset" in iocs.urls
    assert "fake-login-example.com" in iocs.domains
    assert "user@example.com" in iocs.emails
    assert "44d88612fea8a8f36de82e1278abb02f" in iocs.hashes