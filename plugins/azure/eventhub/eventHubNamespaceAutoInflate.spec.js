var expect = require('chai').expect;
var eventHubNamespaceAutoInflate = require('./eventHubNamespaceAutoInflate');
const eventHubs = [
    {
        "kind": "v12.0",
        "location": "eastus",
        "tags": {},
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub'",
        "name": "testHub",
        "type": 'Microsoft.EventHub/Namespaces',
        "location": 'East US',
        "tags": {},
        "minimumTlsVersion": '1.2',
        "publicNetworkAccess": 'Enabled',
        "disableLocalAuth": true,
        "zoneRedundant": true,
        "isAutoInflateEnabled": true,
        "maximumThroughputUnits": 0,
        "kafkaEnabled": false,
        "sku": {
            "name": "Standard",
            "tier": "Standard",
            "capacity": 1
        },
    },
    {   
        "kind": "v12.0",
        "location": "eastus",
        "tags": {},
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub'",
        "name": "testHub",
        "type": 'Microsoft.EventHub/Namespaces',
        "location": 'East US',
        "tags": {},
        "minimumTlsVersion": '1.1',
        "publicNetworkAccess": 'Enabled',
        "disableLocalAuth": true,
        "zoneRedundant": true,
        "isAutoInflateEnabled": false,
        "maximumThroughputUnits": 0,
        "kafkaEnabled": false,
        "sku": {
            "name": "Standard",
            "tier": "Standard",
            "capacity": 1
        },
    },
    {   
        "kind": "v12.0",
        "location": "eastus",
        "tags": {},
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub'",
        "name": "testHub",
        "type": 'Microsoft.EventHub/Namespaces',
        "location": 'East US',
        "tags": {},
        "minimumTlsVersion": '1.1',
        "publicNetworkAccess": 'Enabled',
        "disableLocalAuth": true,
        "zoneRedundant": true,
        "isAutoInflateEnabled": false,
        "maximumThroughputUnits": 0,
        "kafkaEnabled": false,
        "sku": {
            "name": "Premium",
            "tier": "Premium",
            "capacity": 1
        },
    }
];

const createCache = (hub) => {
    return {
        eventHub: {
            listEventHub: {
                'eastus': {
                    data: hub
                }
            }
        }
    }
};

describe('eventHubNamespaceAutoInflate', function() {
    describe('run', function() {
        it('should give passing result if no event hub found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Event Hubs namespaces found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([]);
            eventHubNamespaceAutoInflate.run(cache, {}, callback);
        });

        it('should give failing result if Event Hubs namespace does not have auto-inflate feature enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Event Hubs namespace does not have auto inflate feature enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([eventHubs[1]]);
            eventHubNamespaceAutoInflate.run(cache, {}, callback);
        });

        it('should give passing result if Event Hubs namespace has auto-inflate feature enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Event Hubs namespace has auto inflate feature enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([eventHubs[0]]);
            eventHubNamespaceAutoInflate.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for event hubs', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Event Hubs namespaces:');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(null);
            eventHubNamespaceAutoInflate.run(cache, {}, callback);
        });

        it('should give passing result if event hub namespace is not standard type', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Event Hubs namespace is not a standard namespace');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([eventHubs[2]]);
            eventHubNamespaceAutoInflate.run(cache, {}, callback);
        });
    })
})