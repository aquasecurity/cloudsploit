var expect = require('chai').expect;
var externalNetworkAccess = require('./externalNetworkAccess');

const containerApps = [
    {
      "id": "/subscriptions/123456/resourceGroups/tesr/providers/Microsoft.App/containerapps/test1",
      "name": "test1",
      "type": "Microsoft.App/containerApps",
      "configuration": {
        "ingress": {
            "fqdn": "testfatima.wittysea-8163cba4.australiaeast.azurecontainerapps.io",
            "external": false,
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

describe('externalNetworkAccess', function() {
    describe('run', function() {
        it('should give passing result if no container apps', function(done) {
            const cache = createCache([]);
            externalNetworkAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Container apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for container apps', function(done) {
            const cache = createErrorCache();
            externalNetworkAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Container apps: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give passing result if container app has external network access disabled', function(done) {
            const cache = createCache([containerApps[0]]);
            externalNetworkAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Container app has external network access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if container app does not have external network access disabled', function(done) {
            const cache = createCache([containerApps[1]]);
            externalNetworkAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Container app does not have external network access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
});