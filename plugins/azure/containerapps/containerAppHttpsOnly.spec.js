var expect = require('chai').expect;
var containerAppHttpsOnly = require('./containerAppHttpsOnly');

const containerApps = [
    {
      "id": "/subscriptions/123456/resourceGroups/tesr/providers/Microsoft.App/containerapps/test1",
      "name": "test1",
      "type": "Microsoft.App/containerApps",
      "configuration": {
        "ingress": {
            "fqdn": "testfatima.wittysea-8163cba4.australiaeast.azurecontainerapps.io",
            "external": true,
            "targetPort": 300,
            "exposedPort": 0,
            "transport": "Auto",
            "traffic": [
              {
                "weight": 100,
                "latestRevision": true
              }
            ],
            "customDomains": null,
            "allowInsecure": false,
            "ipSecurityRestrictions": null,
            "corsPolicy": null,
            "clientCertificateMode": "Ignore",
            "stickySessions": {
              "affinity": "none"
            }
          },
        },
      "identity": {
        "type": "SystemAssigned"
      }
    
      },
      {
        "id": "/subscriptions/123456/resourceGroups/tesr/providers/Microsoft.App/containerapps/test2",
        "name": "test2",
        "type": "Microsoft.App/containerApps",
        "configuration": {
            "ingress": {
                "fqdn": "testfatima.wittysea-8163cba4.australiaeast.azurecontainerapps.io",
                "external": true,
                "targetPort": 300,
                "exposedPort": 0,
                "transport": "Auto",
                "traffic": [
                  {
                    "weight": 100,
                    "latestRevision": true
                  }
                ],
                "customDomains": null,
                "allowInsecure": true,
                "ipSecurityRestrictions": null,
                "corsPolicy": null,
                "clientCertificateMode": "Ignore",
                "stickySessions": {
                  "affinity": "none"
                }
              },
            },
        "identity": {
            "type": "None"
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

describe('containerAppMcontainerAppHttpsOnlyanagedIdentity', function() {
    describe('run', function() {
        it('should give passing result if no container apps', function(done) {
            const cache = createCache([]);
            containerAppHttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Container apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for container apps', function(done) {
            const cache = createErrorCache();
            containerAppHttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Container apps: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give passing result if container app is only accessible over HTTPS', function(done) {
            const cache = createCache([containerApps[0]]);
            containerAppHttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Container app is configured with HTTPS only traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if container app is not only accessible over HTTPS', function(done) {
            const cache = createCache([containerApps[1]]);
            containerAppHttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Container app is not configured with HTTPS only traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
});
