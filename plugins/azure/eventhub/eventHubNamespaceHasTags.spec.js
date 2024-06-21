var expect = require('chai').expect;
var eventHubNamespaceHasTags = require('./eventHubNamespaceHasTags');

const eventHubs = [
    {
        "kind": "v12.0",
        "location": "eastus",
        "tags": {"key": "value"},
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub'",
        "name": "testHub",
        "type": 'Microsoft.EventHub/Namespaces',
     
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

describe('eventHubNamespaceHasTags', function() {
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
            eventHubNamespaceHasTags.run(cache, {}, callback);
        });

        it('should give failing result if Event Hubs namespace does not have tags associated', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Event Hubs namespace does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([eventHubs[1]]);
            eventHubNamespaceHasTags.run(cache, {}, callback);
        });

        it('should give passing result if Event Hubs namespace has tags associated', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Event Hubs namespace has tags associated');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([eventHubs[0]]);
            eventHubNamespaceHasTags.run(cache, {}, callback);
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
            eventHubNamespaceHasTags.run(cache, {}, callback);
        });

    })
})