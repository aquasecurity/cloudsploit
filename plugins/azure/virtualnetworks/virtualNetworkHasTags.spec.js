var expect = require('chai').expect;
var virtualNetworkHasTags = require('./virtualNetworkHasTags');

const virtualNetworks = [
    {
        "name": 'test-vnet',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet',
        "type": 'Microsoft.Network/virtualNetworks',
        "tags": { "key": "value" },
        "location": 'eastus',
        "provisioningState": 'Succeeded',
        "virtualNetworkPeerings": [],
        "enableDdosProtection": true
    },
    {
        "name": 'test-vnet',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet',
        "type": 'Microsoft.Network/virtualNetworks',
        "tags": {},
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

describe('virtualNetworkHasTags', function() {
    describe('run', function() {
        it('should give passing result if no virtual networks', function(done) {
            const cache = createCache([]);
            virtualNetworkHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Networks found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if virtual Network does not have tags associated', function(done) {
            const cache = createCache([virtualNetworks[1]]);
            virtualNetworkHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual Network does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Virtual Networks', function(done) {
            const cache = createErrorCache();
            virtualNetworkHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Networks:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if virtual Network has tags associated', function(done) {
            const cache = createCache([virtualNetworks[0]]);
            virtualNetworkHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Network has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 