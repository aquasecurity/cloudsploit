var expect = require('chai').expect;
var openUDP = require('./openUDP');

const networkSecurityGroups = [
    {
        "name": "aadds-nsg",
        "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg",
        "etag": "W/\"a1bb27cd-711f-4ede-b673-2fe8e7e07eee\"",
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "resourceGuid": "4a6b1ca1-a123-4829-a25d-1a6bcde3fg45",
        "securityRules": [
            {
                "name": "AllowPSRemoting",
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg/securityRules/AllowPSRemoting",
                "etag": "W/\"a1bb27cd-711f-4ede-b673-2fe8e7e07eee\"",
                "type": "Microsoft.Network/networkSecurityGroups/securityRules",
                "properties": {
                    "provisioningState": "Succeeded",
                    "protocol": "UDP",
                    "sourcePortRange": "*",
                    "destinationPortRange": "5986",
                    "sourceAddressPrefix": "AzureActiveDirectoryDomainServices",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "priority": 301,
                    "direction": "Inbound",
                }
            }
        ],
        "defaultSecurityRules": [],
        "subnets": [
            {
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/virtualNetworks/aadds-vnet/subnets/aadds-subnet"
            }
        ]
    },
    {
        "name": "test-vm-1-nsg",
        "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-1-nsg",
        "etag": "W/\"9479cb49-b812-4f0f-825b-2960bfcd14e3\"",
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "resourceGuid": "12a3456b-8cc0-4d9e-aa71-99cdc67b4506",
        "securityRules": [
            {
                "name": "AllowRD",
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg/securityRules/AllowRD",
                "etag": "W/\"a1bb27cd-711f-4ede-b673-2fe8e7e07eee\"",
                "type": "Microsoft.Network/networkSecurityGroups/securityRules",
                "properties": {
                    "provisioningState": "Succeeded",
                    "protocol": "UDP",
                    "sourcePortRange": "*",
                    "destinationPortRange": "5986",
                    "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "priority": 301,
                    "direction": "Inbound",
                }
            }
        ],
        "defaultSecurityRules": [],
        "networkInterfaces": [
            {
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkInterfaces/test-vm-1969"
            }
        ]
    },
    {
        "name": "test-vm-2-nsg",
        "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-2-nsg",
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "securityRules": [
            {
                "name": "AllowAnyProtocolDns",
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-2-nsg/securityRules/AllowAnyProtocolDns",
                "type": "Microsoft.Network/networkSecurityGroups/securityRules",
                "properties": {
                    "provisioningState": "Succeeded",
                    "protocol": "*",
                    "sourcePortRange": "*",
                    "destinationPortRange": "53",
                    "sourceAddressPrefix": "0.0.0.0/0",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "priority": 301,
                    "direction": "Inbound",
                }
            }
        ],
        "defaultSecurityRules": []
    },
    {
        "name": "test-vm-3-nsg",
        "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-3-nsg",
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "securityRules": [
            {
                "name": "AllowNtpFromAnyIpv6",
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-3-nsg/securityRules/AllowNtpFromAnyIpv6",
                "type": "Microsoft.Network/networkSecurityGroups/securityRules",
                "properties": {
                    "provisioningState": "Succeeded",
                    "protocol": "Udp",
                    "sourcePortRange": "*",
                    "destinationPortRange": "123",
                    "sourceAddressPrefix": "::/0",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "priority": 302,
                    "direction": "Inbound",
                }
            }
        ],
        "defaultSecurityRules": []
    },
    {
        "name": "test-vm-4-nsg",
        "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-4-nsg",
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "securityRules": [
            {
                "name": "AllowSsdpFromPrefixes",
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-4-nsg/securityRules/AllowSsdpFromPrefixes",
                "type": "Microsoft.Network/networkSecurityGroups/securityRules",
                "properties": {
                    "provisioningState": "Succeeded",
                    "protocol": "Udp",
                    "sourcePortRange": "*",
                    "destinationPortRange": "1900",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "priority": 303,
                    "direction": "Inbound",
                    "sourceAddressPrefixes": [
                        "10.0.0.0/24",
                        "0.0.0.0/0"
                    ]
                }
            }
        ],
        "defaultSecurityRules": []
    }
];

const createCache = (securityGroups) => {
    return {
        networkSecurityGroups: {
            listAll: {
                'eastus': {
                    data: securityGroups
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        networkSecurityGroups: {
            listAll: {
                'eastus': {}
            }
        }
    };
};

describe('openUDP', function() {
    describe('run', function() {
        it('should give passing result if no Network Security Groups found', function(done) {
            const cache = createCache([]);
            openUDP.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No security groups found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Network Security Groups', function(done) {
            const cache = createErrorCache();
            openUDP.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Network Security Groups:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if the security group does not have open UDP ports for internet access', function(done) {
            const cache = createCache([networkSecurityGroups[0]]);
            openUDP.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('does not have open UDP ports for internet access');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if the security group has open UDP ports for internet access', function(done) {
            const cache = createCache([networkSecurityGroups[1]]);
            openUDP.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('has open UDP ports for internet access');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if the security group allows any protocol from 0.0.0.0/0', function(done) {
            const cache = createCache([networkSecurityGroups[2]]);
            openUDP.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('has open UDP ports for internet access');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if the security group allows UDP from any IPv6 address', function(done) {
            const cache = createCache([networkSecurityGroups[3]]);
            openUDP.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('has open UDP ports for internet access');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if the security group allows UDP from an open source address prefix in sourceAddressPrefixes', function(done) {
            const cache = createCache([networkSecurityGroups[4]]);
            openUDP.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('has open UDP ports for internet access');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
