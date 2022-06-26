var expect = require('chai').expect;
var excessiveSecurityGroups = require('./excessiveSecurityGroups');

const networkSecurityGroups = [
    {
        "name": "aadds-nsg",
        "id": "/subscriptions/ab12c345-def7-890g-a1b2-28fc0d22117e/resourceGroups/test-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg",
        "etag": "W/\"a1bb27cd-711f-4ede-b673-2fe8e7e07eee\"",
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "resourceGuid": "4a6b1ca1-a123-4829-a25d-1a6bcde3fg45",
        "securityRules": [],
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
        "securityRules": [],
        "defaultSecurityRules": [],
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

describe('excessiveSecurityGroups', function() {
    describe('run', function() {
        it('should give passing result if no Network Security Groups found', function(done) {
            const cache = createCache([]);
            excessiveSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No security groups found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Network Security Groups', function(done) {
            const cache = createErrorCache();
            excessiveSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Network Security Groups:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if the count of Network Security Group is Acceptable', function(done) {
            const cache = createCache(networkSecurityGroups);
            excessiveSecurityGroups.run(cache, { excessive_security_groups_fail: 5, excessive_security_groups_warn: 4 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Acceptable number of security groups:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if the count of Network Security Group is Excessive', function(done) {
            const cache = createCache(networkSecurityGroups);
            excessiveSecurityGroups.run(cache, { excessive_security_groups_fail: 2, excessive_security_groups_warn: 1 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Excessive number of security groups:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give warning result if the count of Network Security Group is Large', function(done) {
            const cache = createCache(networkSecurityGroups);
            excessiveSecurityGroups.run(cache, { excessive_security_groups_fail: 3, excessive_security_groups_warn: 2 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].message).to.include('Large number of security groups:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});