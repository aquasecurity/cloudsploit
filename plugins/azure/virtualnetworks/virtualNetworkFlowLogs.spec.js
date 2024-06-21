var expect = require('chai').expect;
var virtualNetworkFlowLogs = require('./virtualNetworkFlowLogs');

const virtualNetworks = [
    {
        "name": 'test-vnet',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet',
        "type": 'Microsoft.Network/virtualNetworks',
        "tags": { "key": "value" },
        "location": 'eastus',
        "provisioningState": 'Succeeded',
        "virtualNetworkPeerings": [],
        "enableDdosProtection": true,
        "flowLogs":[
            {
                "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus/flowLogs/test-flowlog',

            }
        ],
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

describe('virtualNetworkFlowLogs', function() {
    describe('run', function() {
        it('should give passing result if no virtual networks', function(done) {
            const cache = createCache([]);
            virtualNetworkFlowLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Networks found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if virtual Network does not have flow logs enabled', function(done) {
            const cache = createCache([virtualNetworks[1]]);
            virtualNetworkFlowLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual Network does not have flow logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Virtual Networks', function(done) {
            const cache = createErrorCache();
            virtualNetworkFlowLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Networks:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if virtual Network has flow logs enabled', function(done) {
            const cache = createCache([virtualNetworks[0]]);
            virtualNetworkFlowLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Network has flow logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 