resource "%(name)s" {
        protocol C;
        startup {
                wfc-timeout  15;
                degr-wfc-timeout 60;
        }
        net {
                cram-hmac-alg sha1;
                shared-secret "%(secret)s";
        }
        on %(primary_fqdn)s {
                device /dev/%(primary_drbd)s;
                disk /dev/%(primary_loop)s;
                address ipv4 %(primary_ip)s:%(primary_port)s;
                meta-disk internal;
        }
        on %(secondary_fqdn)s {
                device /dev/%(secondary_drbd)s;
                disk /dev/%(secondary_loop)s;
                address ipv4 %(secondary_ip)s:%(secondary_port)s;
                meta-disk internal;
        }
}
