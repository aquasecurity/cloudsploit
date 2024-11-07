var expect = require('chai').expect;
var containerAppIPRestriction = require('./containerAppIPRestriction');

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
            "ipSecurityRestrictions": [
                {
                    "action":'Allow',
                    "description":'dummy',
                    "ipAddressRange": '00000',
                    "name": 'test'
                }
            ],
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

describe('containerAppIPRestriction', function() {
    describe('run', function() {
        it('should give passing result if no container apps', function(done) {
            const cache = createCache([]);
            containerAppIPRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Container apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for container apps', function(done) {
            const cache = createErrorCache();
            containerAppIPRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Container apps: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give passing result if container app has IP restrictions configured', function(done) {
            const cache = createCache([containerApps[0]]);
            containerAppIPRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Container app has IP restrictions configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if container app does not have IP restrictions configured', function(done) {
            const cache = createCache([containerApps[1]]);
            containerAppIPRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Container app does not have IP restrictions configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
});
