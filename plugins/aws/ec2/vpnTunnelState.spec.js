var expect = require('chai').expect;
const vpnTunnelState = require('./vpnTunnelState');

const describeVpnConnections = [
    {
        "CustomerGatewayConfiguration": "",
        "CustomerGatewayId": "cgw-04fe197456aa25733",
        "Category": "VPN",
        "State": "available",
        "Type": "ipsec.1",
        "VpnConnectionId": "vpn-0f482914f2c2c36ed",
        "TransitGatewayId": "tgw-08e8a28e47ca6583b",
        "Options": {
            "EnableAcceleration": false,
            "StaticRoutesOnly": false,
            "LocalIpv4NetworkCidr": "0.0.0.0/0",
            "RemoteIpv4NetworkCidr": "0.0.0.0/0",
            "TunnelInsideIpVersion": "ipv4"
        },
        "Routes": [],
        "Tags": [
            {
                "Key": "Name",
                "Value": "akd-33"
            }
        ],
        "VgwTelemetry": [
            {
                "AcceptedRouteCount": 0,
                "LastStatusChange": "2020-12-29T20:09:58+00:00",
                "OutsideIpAddress": "3.231.123.34",
                "Status": "UP",
                "StatusMessage": "IPSEC IS UP"
            },
            {
                "AcceptedRouteCount": 0,
                "LastStatusChange": "2020-12-29T20:12:32+00:00",
                "OutsideIpAddress": "18.210.70.26",
                "Status": "UP",
                "StatusMessage": "IPSEC IS UP"
            }
        ]
    },
    {
        "CustomerGatewayConfiguration": "",
        "CustomerGatewayId": "cgw-04fe197456aa25733",
        "Category": "VPN",
        "State": "available",
        "Type": "ipsec.1",
        "VpnConnectionId": "vpn-0f482914f2c2c36ed",
        "TransitGatewayId": "tgw-08e8a28e47ca6583b",
        "Options": {
            "EnableAcceleration": false,
            "StaticRoutesOnly": false,
            "LocalIpv4NetworkCidr": "0.0.0.0/0",
            "RemoteIpv4NetworkCidr": "0.0.0.0/0",
            "TunnelInsideIpVersion": "ipv4"
        },
        "Routes": [],
        "Tags": [
            {
                "Key": "Name",
                "Value": "akd-33"
            }
        ],
        "VgwTelemetry": [
            {
                "AcceptedRouteCount": 0,
                "LastStatusChange": "2020-12-29T20:09:58+00:00",
                "OutsideIpAddress": "3.231.123.34",
                "Status": "UP",
                "StatusMessage": "IPSEC IS UP"
            },
            {
                "AcceptedRouteCount": 0,
                "LastStatusChange": "2020-12-29T20:12:32+00:00",
                "OutsideIpAddress": "18.210.70.26",
                "Status": "DOWN",
                "StatusMessage": "IPSEC IS DOWN"
            }
        ]
    },
    {
        "CustomerGatewayConfiguration": "",
        "CustomerGatewayId": "cgw-04fe197456aa25733",
        "Category": "VPN",
        "State": "available",
        "Type": "ipsec.1",
        "VpnConnectionId": "vpn-0f482914f2c2c36ed",
        "TransitGatewayId": "tgw-08e8a28e47ca6583b",
        "Options": {
            "EnableAcceleration": false,
            "StaticRoutesOnly": false,
            "LocalIpv4NetworkCidr": "0.0.0.0/0",
            "RemoteIpv4NetworkCidr": "0.0.0.0/0",
            "TunnelInsideIpVersion": "ipv4"
        },
        "Routes": [],
        "Tags": [
            {
                "Key": "Name",
                "Value": "akd-33"
            }
        ],
        "VgwTelemetry": []
    }
];

const createCache = (describeVpnConnections, describeVpnConnectionsErr) => {
    return {
        ec2: {
            describeVpnConnections: {
                'us-east-1': {
                    err: describeVpnConnectionsErr,
                    data: describeVpnConnections
                }
            },
        }
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeVpnConnections: {
                'us-east-1': null
            }
        }
    };
};

describe('vpnTunnelState', function () {
    describe('run', function () {
        it('should PASS if VPN connection has all tunnels UP', function (done) {
            const cache = createCache([describeVpnConnections[0]], null);
            vpnTunnelState.run(cache, { enable_vpn_tunnel_state: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if VPN connection has tunnel down', function (done) {
            const cache = createCache([describeVpnConnections[1]], null);
            vpnTunnelState.run(cache, { enable_vpn_tunnel_state: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if VPN connection does not have any tunnel configured', function (done) {
            const cache = createCache([describeVpnConnections[2]], null);
            vpnTunnelState.run(cache, { enable_vpn_tunnel_state: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no VPN connections found', function (done) {
            const cache = createCache([], null);
            vpnTunnelState.run(cache, { enable_vpn_tunnel_state: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNWON if unable to query for VPN connections', function (done) {
            const cache = createCache([], { message: 'Unable to query for VPN connections'});
            vpnTunnelState.run(cache, { enable_vpn_tunnel_state: 'true' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe VPN connections response not found', function (done) {
            const cache = createNullCache();
            vpnTunnelState.run(cache, { enable_vpn_tunnel_state: 'true' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
