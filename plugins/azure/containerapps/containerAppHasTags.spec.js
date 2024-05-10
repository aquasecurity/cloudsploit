var expect = require('chai').expect;
var containerAppHasTags = require('./containerAppHasTags');

const containerApps = [
    {
      "id": "/subscriptions/123456/resourceGroups/tesr/providers/Microsoft.App/containerapps/test1",
      "name": "test1",
      "type": "Microsoft.App/containerApps",
      "identity": {
        "type": "SystemAssigned"
      },
      "tags": { 'key': 'value' },
    
      },
      {
        "id": "/subscriptions/123456/resourceGroups/tesr/providers/Microsoft.App/containerapps/test2",
        "name": "test2",
        "type": "Microsoft.App/containerApps",
        "identity": {
            "type": "None"
        },
        "tags": { },
      },
];

const createCache = (container) => {
    return {
        containerApps: {
            list: {
                'eastus': {
                    data: container
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        containerApps: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('containerAppHasTags', function() {
    describe('run', function() {
        it('should give passing result if no container apps', function(done) {
            const cache = createCache([]);
            containerAppHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Container apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for container apps', function(done) {
            const cache = createErrorCache();
            containerAppHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Container apps: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give passing result if container app has tags', function(done) {
            const cache = createCache([containerApps[0]]);
            containerAppHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Container app has tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if container app does not have tags', function(done) {
            const cache = createCache([containerApps[1]]);
            containerAppHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Container app does not have tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
});