var expect = require('chai').expect;
var containerAppVolumeMount = require('./containerAppVolumeMount');

const containerApps = [
    {
      "id": "/subscriptions/123456/resourceGroups/tesr/providers/Microsoft.App/containerapps/test1",
      "name": "test1",
      "type": "Microsoft.App/containerApps",
      "identity": {
        "type": "SystemAssigned"
      },
      "template": {
        "volumes": [{
            "name": "test",
            "storageType": "Secret"
        }]
      }
    
      },
      {
        "id": "/subscriptions/123456/resourceGroups/tesr/providers/Microsoft.App/containerapps/test2",
        "name": "test2",
        "type": "Microsoft.App/containerApps",
        "identity": {
            "type": "None"
        },
        "template": {
            "volumes": []
        }
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

describe('containerAppVolumeMount', function() {
    describe('run', function() {
        it('should give passing result if no container apps', function(done) {
            const cache = createCache([]);
            containerAppVolumeMount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Container apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for container apps', function(done) {
            const cache = createErrorCache();
            containerAppVolumeMount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Container apps: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give passing result if Container app has volume mount configured', function(done) {
            const cache = createCache([containerApps[0]]);
            containerAppVolumeMount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Container app has volume mount configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Container app does not have volume mount configured', function(done) {
            const cache = createCache([containerApps[1]]);
            containerAppVolumeMount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Container app does not have volume mount configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
});