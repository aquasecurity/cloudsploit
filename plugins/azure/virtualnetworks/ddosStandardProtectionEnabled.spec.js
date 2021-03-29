var expect = require('chai').expect;
var ddosStandardProtectionEnabled = require('./ddosStandardProtectionEnabled');

const virtualNetworks = [
    {
        "name": 'test-vnet',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet',
        "type": 'Microsoft.Network/virtualNetworks',
        "location": 'eastus',
        "provisioningState": 'Succeeded',
        "virtualNetworkPeerings": [],
        "enableDdosProtection": true
    },
    {
        "name": 'test-vnet',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet',
        "type": 'Microsoft.Network/virtualNetworks',
        "location": 'eastus',
        "provisioningState": 'Succeeded',
        "virtualNetworkPeerings": [],
        "enableDdosProtection": false
    }
];

const createCache = (virtualNetworks) => {
    return {
        virtualNetworks: {
            listAll: {
                'eastus': {
                    data: virtualNetworks
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        virtualNetworks: {
            listAll: {
                'eastus': {}
            }
        }
    };
};

describe('ddosStandardProtectionEnabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual networks', function(done) {
            const cache = createCache([]);
            ddosStandardProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Networks found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if DDoS standard protection is not enabled for virtual network', function(done) {
            const cache = createCache([virtualNetworks[1]]);
            ddosStandardProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('DDoS Standard Protection is not enabled for Microsoft Azure Virtual Network');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Virtual Networks', function(done) {
            const cache = createErrorCache();
            ddosStandardProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Networks:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if DDoS standard protection is enabled for virtual network', function(done) {
            const cache = createCache([virtualNetworks[0]]);
            ddosStandardProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('DDoS Standard Protection is enabled for Microsoft Azure Virtual Network');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 