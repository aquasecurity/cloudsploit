var expect = require('chai').expect;
var openAllPorts = require('./openAllPorts');

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
                    "protocol": "Tcp",
                    "sourcePortRange": "*",
                    "destinationPortRange": "5986",
                    "sourceAddressPrefix": "AzureActiveDirectoryDomainServices",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "priority": 301,
                    "direction": "Inbound",
                    "sourcePortRanges": [],
                    "destinationPortRanges": [],
                    "sourceAddressPrefixes": [],
                    "destinationAddressPrefixes": []
                }
            },
            {
                "name": "AllowRD",
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg/securityRules/AllowRD",
                "etag": "W/\"a1bb27cd-711f-4ede-b673-2fe8e7e07eee\"",
                "type": "Microsoft.Network/networkSecurityGroups/securityRules",
                "properties": {
                    "provisioningState": "Succeeded",
                    "protocol": "Tcp",
                    "sourcePortRange": "*",
                    "destinationPortRange": "3389",
                    "sourceAddressPrefix": "CorpNetSaw",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "priority": 201,
                    "direction": "Inbound",
                    "sourcePortRanges": [],
                    "destinationPortRanges": [],
                    "sourceAddressPrefixes": [],
                    "destinationAddressPrefixes": []
                }
            }
        ],
        "defaultSecurityRules": [
            {
                "name": "AllowVnetInBound",
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg/defaultSecurityRules/AllowVnetInBound",
                "etag": "W/\"a1bb27cd-711f-4ede-b673-2fe8e7e07eee\"",
                "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
                "properties": {
                    "provisioningState": "Succeeded",
                    "description": "Allow inbound traffic from all VMs in VNET",
                    "protocol": "*",
                    "sourcePortRange": "*",
                    "destinationPortRange": "*",
                    "sourceAddressPrefix": "VirtualNetwork",
                    "destinationAddressPrefix": "VirtualNetwork",
                    "access": "Allow",
                    "priority": 65000,
                    "direction": "Inbound",
                    "sourcePortRanges": [],
                    "destinationPortRanges": [],
                    "sourceAddressPrefixes": [],
                    "destinationAddressPrefixes": []
                }
            },
            {
                "name": "AllowAzureLoadBalancerInBound",
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg/defaultSecurityRules/AllowAzureLoadBalancerInBound",
                "etag": "W/\"a1bb27cd-711f-4ede-b673-2fe8e7e07eee\"",
                "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
                "properties": {
                    "provisioningState": "Succeeded",
                    "description": "Allow inbound traffic from azure load balancer",
                    "protocol": "*",
                    "sourcePortRange": "*",
                    "destinationPortRange": "*",
                    "sourceAddressPrefix": "AzureLoadBalancer",
                    "destinationAddressPrefix": "*",
                    "access": "Allow",
                    "priority": 65001,
                    "direction": "Inbound",
                    "sourcePortRanges": [],
                    "destinationPortRanges": [],
                    "sourceAddressPrefixes": [],
                    "destinationAddressPrefixes": []
                }
            },
            {
                "name": "DenyAllInBound",
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg/defaultSecurityRules/DenyAllInBound",
                "etag": "W/\"a1bb27cd-711f-4ede-b673-2fe8e7e07eee\"",
                "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
                "properties": {
                    "provisioningState": "Succeeded",
                    "description": "Deny all inbound traffic",
                    "protocol": "*",
                    "sourcePortRange": "*",
                    "destinationPortRange": "*",
                    "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "*",
                    "access": "Deny",
                    "priority": 65500,
                    "direction": "Inbound",
                    "sourcePortRanges": [],
                    "destinationPortRanges": [],
                    "sourceAddressPrefixes": [],
                    "destinationAddressPrefixes": []
                }
            },
            {
                "name": "AllowVnetOutBound",
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg/defaultSecurityRules/AllowVnetOutBound",
                "etag": "W/\"a1bb27cd-711f-4ede-b673-2fe8e7e07eee\"",
                "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
                "properties": {
                    "provisioningState": "Succeeded",
                    "description": "Allow outbound traffic from all VMs to all VMs in VNET",
                    "protocol": "*",
                    "sourcePortRange": "*",
                    "destinationPortRange": "*",
                    "sourceAddressPrefix": "VirtualNetwork",
                    "destinationAddressPrefix": "VirtualNetwork",
                    "access": "Allow",
                    "priority": 65000,
                    "direction": "Outbound",
                    "sourcePortRanges": [],
                    "destinationPortRanges": [],
                    "sourceAddressPrefixes": [],
                    "destinationAddressPrefixes": []
                }
            },
            {
                "name": "AllowInternetOutBound",
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg/defaultSecurityRules/AllowInternetOutBound",
                "etag": "W/\"a1bb27cd-711f-4ede-b673-2fe8e7e07eee\"",
                "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
                "properties": {
                    "provisioningState": "Succeeded",
                    "description": "Allow outbound traffic from all VMs to Internet",
                    "protocol": "*",
                    "sourcePortRange": "*",
                    "destinationPortRange": "*",
                    "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "Internet",
                    "access": "Allow",
                    "priority": 65001,
                    "direction": "Outbound",
                    "sourcePortRanges": [],
                    "destinationPortRanges": [],
                    "sourceAddressPrefixes": [],
                    "destinationAddressPrefixes": []
                }
            },
            {
                "name": "DenyAllOutBound",
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg/defaultSecurityRules/DenyAllOutBound",
                "etag": "W/\"a1bb27cd-711f-4ede-b673-2fe8e7e07eee\"",
                "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
                "properties": {
                    "provisioningState": "Succeeded",
                    "description": "Deny all outbound traffic",
                    "protocol": "*",
                    "sourcePortRange": "*",
                    "destinationPortRange": "*",
                    "sourceAddressPrefix": "*",
                    "destinationAddressPrefix": "*",
                    "access": "Deny",
                    "priority": 65500,
                    "direction": "Outbound",
                    "sourcePortRanges": [],
                    "destinationPortRanges": [],
                    "sourceAddressPrefixes": [],
                    "destinationAddressPrefixes": []
                }
            }
        ],
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
            "name": "AllowPSRemoting",
            "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg/securityRules/AllowPSRemoting",
            "etag": "W/\"a1bb27cd-711f-4ede-b673-2fe8e7e07eee\"",
            "type": "Microsoft.Network/networkSecurityGroups/securityRules",
            "properties": {
                "provisioningState": "Succeeded",
                "protocol": "*",
                "sourcePortRange": "*",
                "sourceAddressPrefix": "*",
                "destinationAddressPrefix": "*",
                "access": "Allow",
                "priority": 301,
                "direction": "Inbound",
                "sourcePortRanges": [],
                "destinationPortRanges": [
                    "5986",
                    "5987",
                    "*"
                ],
                "sourceAddressPrefixes": [],
                "destinationAddressPrefixes": []
            }
        },
        ],
        "defaultSecurityRules": [
        {
            "name": "AllowVnetInBound",
            "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-1-nsg/defaultSecurityRules/AllowVnetInBound",
            "etag": "W/\"9479cb49-b812-4f0f-825b-2960bfcd14e3\"",
            "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
            "properties": {
                "provisioningState": "Succeeded",
                "description": "Allow inbound traffic from all VMs in VNET",
                "protocol": "*",
                "sourcePortRange": "*",
                "destinationPortRange": "*",
                "sourceAddressPrefix": "VirtualNetwork",
                "destinationAddressPrefix": "VirtualNetwork",
                "access": "Allow",
                "priority": 65000,
                "direction": "Inbound",
                "sourcePortRanges": [],
                "destinationPortRanges": [],
                "sourceAddressPrefixes": [],
                "destinationAddressPrefixes": []
            }
        },
        {
            "name": "AllowAzureLoadBalancerInBound",
            "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-1-nsg/defaultSecurityRules/AllowAzureLoadBalancerInBound",
            "etag": "W/\"9479cb49-b812-4f0f-825b-2960bfcd14e3\"",
            "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
            "properties": {
                "provisioningState": "Succeeded",
                "description": "Allow inbound traffic from azure load balancer",
                "protocol": "*",
                "sourcePortRange": "*",
                "destinationPortRange": "*",
                "sourceAddressPrefix": "AzureLoadBalancer",
                "destinationAddressPrefix": "*",
                "access": "Allow",
                "priority": 65001,
                "direction": "Inbound",
                "sourcePortRanges": [],
                "destinationPortRanges": [],
                "sourceAddressPrefixes": [],
                "destinationAddressPrefixes": []
            }
        },
        {
            "name": "DenyAllInBound",
            "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-1-nsg/defaultSecurityRules/DenyAllInBound",
            "etag": "W/\"9479cb49-b812-4f0f-825b-2960bfcd14e3\"",
            "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
            "properties": {
                "provisioningState": "Succeeded",
                "description": "Deny all inbound traffic",
                "protocol": "*",
                "sourcePortRange": "*",
                "destinationPortRange": "*",
                "sourceAddressPrefix": "*",
                "destinationAddressPrefix": "*",
                "access": "Deny",
                "priority": 65500,
                "direction": "Inbound",
                "sourcePortRanges": [],
                "destinationPortRanges": [],
                "sourceAddressPrefixes": [],
                "destinationAddressPrefixes": []
            }
        },
        {
            "name": "AllowVnetOutBound",
            "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-1-nsg/defaultSecurityRules/AllowVnetOutBound",
            "etag": "W/\"9479cb49-b812-4f0f-825b-2960bfcd14e3\"",
            "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
            "properties": {
                "provisioningState": "Succeeded",
                "description": "Allow outbound traffic from all VMs to all VMs in VNET",
                "protocol": "*",
                "sourcePortRange": "*",
                "destinationPortRange": "*",
                "sourceAddressPrefix": "VirtualNetwork",
                "destinationAddressPrefix": "VirtualNetwork",
                "access": "Allow",
                "priority": 65000,
                "direction": "Outbound",
                "sourcePortRanges": [],
                "destinationPortRanges": [],
                "sourceAddressPrefixes": [],
                "destinationAddressPrefixes": []
            }
        },
        {
            "name": "AllowInternetOutBound",
            "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-1-nsg/defaultSecurityRules/AllowInternetOutBound",
            "etag": "W/\"9479cb49-b812-4f0f-825b-2960bfcd14e3\"",
            "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
            "properties": {
                "provisioningState": "Succeeded",
                "description": "Allow outbound traffic from all VMs to Internet",
                "protocol": "*",
                "sourcePortRange": "*",
                "destinationPortRange": "*",
                "sourceAddressPrefix": "*",
                "destinationAddressPrefix": "Internet",
                "access": "Allow",
                "priority": 65001,
                "direction": "Outbound",
                "sourcePortRanges": [],
                "destinationPortRanges": [],
                "sourceAddressPrefixes": [],
                "destinationAddressPrefixes": []
            }
        },
        {
            "name": "DenyAllOutBound",
            "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-1-nsg/defaultSecurityRules/DenyAllOutBound",
            "etag": "W/\"9479cb49-b812-4f0f-825b-2960bfcd14e3\"",
            "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
            "properties": {
                "provisioningState": "Succeeded",
                "description": "Deny all outbound traffic",
                "protocol": "*",
                "sourcePortRange": "*",
                "destinationPortRange": "*",
                "sourceAddressPrefix": "*",
                "destinationAddressPrefix": "*",
                "access": "Deny",
                "priority": 65500,
                "direction": "Outbound",
                "sourcePortRanges": [],
                "destinationPortRanges": [],
                "sourceAddressPrefixes": [],
                "destinationAddressPrefixes": []
            }
        }
        ],
        "networkInterfaces": [
            {
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkInterfaces/test-vm-1969"
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
        "securityRules": [],
        "defaultSecurityRules": [],
        "networkInterfaces": [
            {
                "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkInterfaces/test-vm-1969"
            }
        ]
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

describe('openAllPorts', function() {
    describe('run', function() {
        it('should give passing result if no Network Security Groups found', function(done) {
            const cache = createCache([]);
            openAllPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No security groups found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Network Security Groups', function(done) {
            const cache = createErrorCache();
            openAllPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Network Security Groups:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if the Network Security Group has no public open ports found', function(done) {
            const cache = createCache([networkSecurityGroups[0]]);
            openAllPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No public open ports found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if the Network Security Group has some public open ports', function(done) {
            const cache = createCache([networkSecurityGroups[1]]);
            openAllPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});