var expect = require('chai').expect;
var eventHubPublicAccess = require('./eventHubPublicAccess');

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
        "publicNetworkAccess": 'Disabled',
        "disableLocalAuth": true,
        "zoneRedundant": true,
        "isAutoInflateEnabled": false,
        "maximumThroughputUnits": 0,
        "kafkaEnabled": false
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
    },
    {
        "kind": "v12.0",
        "location": "eastus",
        "tags": {},
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub'",
        "name": "testHub2",
        "type": 'Microsoft.EventHub/Namespaces',
        "location": 'East US',
        "tags": {},
        "sku": {
            "name": "Basic",
            "tier": "Basic",
            "capacity": 1
        },
        "minimumTlsVersion": '1.2',
        "publicNetworkAccess": 'Enabled',
        "disableLocalAuth": true,
        "isAutoInflateEnabled": false,
        "maximumThroughputUnits": 0,
        "kafkaEnabled": false
    },
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

describe('eventHubPublicAccess', function() {
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
            eventHubPublicAccess.run(cache, {}, callback);
        });

        it('should give failing result if event hub is publicly accessible', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Event Hubs namespace is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([eventHubs[1]]);
            eventHubPublicAccess.run(cache, {}, callback);
        });

        it('should give passing result if eventHub is not publicly accessible', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Event Hubs namespace is not publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([eventHubs[0]]);
            eventHubPublicAccess.run(cache, {}, callback);
        });

        it('should give passing result if eventHub is of basic tier', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Event Hubs namespace tier is basic');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([eventHubs[2]]);
            eventHubPublicAccess.run(cache, {}, callback);
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
            eventHubPublicAccess.run(cache, {}, callback);
        });
    })
})