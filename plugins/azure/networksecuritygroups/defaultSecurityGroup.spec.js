var expect = require('chai').expect;
var defaultSecurityGroup = require('./defaultSecurityGroup');

const networkSecurityGroups = [
    {
        "name": "aadds-nsg",
        "id": "/subscriptions/dce9d1sa-ebf6-437f-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg",
        "etag": "W/\"a1bb27cd-711f-4ede-b673-2fe8e7e07eee\"",
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "resourceGuid": "4a6b1ca1-a123-4829-a25d-1a6bcde3fg45",
        "securityRules": [],
        "defaultSecurityRules": [{
                "name": "DenyAllInBound",
                "id": "/subscriptions/dce9d1sa-ebf6-437f-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg/defaultSecurityRules/DenyAllInBound",
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
                "name": "DenyAllOutBound",
                "id": "/subscriptions/dce9d1sa-ebf6-437f-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg/defaultSecurityRules/DenyAllOutBound",
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
        "subnets": []
    },
    {
        "name": "test-vm-1-nsg",
        "id": "/subscriptions/dce9d1sa-ebf6-437f-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-1-nsg",
        "etag": "W/\"9479cb49-b812-4f0f-825b-2960bfcd14e3\"",
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "resourceGuid": "12a3456b-7dd8-4d9e-aa71-99cdc67b4506",
        "securityRules": [],
        "defaultSecurityRules": [{
            "name": "DenyAllOutBound",
            "id": "/subscriptions/dce9d1sa-ebf6-437f-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-1-nsg/defaultSecurityRules/DenyAllOutBound",
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
            }
        }],
        "networkInterfaces": [{
            "id": "/subscriptions/dce9d1sa-ebf6-437f-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkInterfaces/test-vm-1969"
        }]
    },
    {
        "name": "test-vm-1-nsg",
        "id": "/subscriptions/dce9d1sa-ebf6-437f-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/test-vm-1-nsg",
        "etag": "W/\"9479cb49-b812-4f0f-825b-2960bfcd14e3\"",
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "resourceGuid": "12a3456b-7dd8-4d9e-aa71-99cdc67b4506",
        "securityRules": [],
        "defaultSecurityRules": [],
        "networkInterfaces": [{
            "id": "/subscriptions/dce9d1sa-ebf6-437f-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkInterfaces/test-vm-1969"
        }]
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

describe('defaultSecurityGroup', function() {
    describe('run', function() {
        it('should give passing result if no Network Security Groups found', function(done) {
            const cache = createCache([]);
            defaultSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No security groups found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Network Security Groups', function(done) {
            const cache = createErrorCache();
            defaultSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Network Security Groups:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if the Network Security Group has all required default inbound and outbound rules', function(done) {
            const cache = createCache([networkSecurityGroups[0]]);
            defaultSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has all required default inbound and outbound rules');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Network Security Group does not have required default inbound and outbound rules', function(done) {
            const cache = createCache([networkSecurityGroups[1]]);
            defaultSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have required default inbound and outbound rules:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Network Security Group is missing one or more default inbound or outbound rules', function(done) {
            const cache = createCache([networkSecurityGroups[2]]);
            defaultSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('is missing one or more default inbound or outbound rules');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});