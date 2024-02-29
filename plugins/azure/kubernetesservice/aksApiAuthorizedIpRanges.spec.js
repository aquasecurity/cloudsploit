var expect = require('chai').expect;
var aksApiAuthorizedIpRanges = require('./aksApiAuthorizedIpRanges.js');
const listCluster = [
    {
        "id": "/subscriptions/1234/resourcegroups/ABSBAKS2/providers/Microsoft.ContainerService/managedClusters/absbaks2",
        "location": "eastus",
        'tags': { 'key': 'value' },
        "name": "absbaks2",
        "apiServerAccessProfile": {
            "authorizedIPRanges": [
              "10.0.0.0/24"
            ]
          },
    },
        {
        "id": "/subscriptions/1234/resourcegroups/ABSBAKS2/providers/Microsoft.ContainerService/managedClusters/absbaks2",
        "location": "eastus",
        'tags': {},
        "name": "absbaks2",
        "type": "Microsoft.ContainerService/ManagedClusters",
        "sku": {
            "name": "Basic",
            "tier": "Free"
        },
        "apiServerAccessProfile": {
            "enablePrivateCluster": false
        }
    }
]

const createCache = (err, list) => {
    return {
        managedClusters: {
            list: {
                'eastus': {
                    err: err,
                    data: list
                }
            }
        }
    }
};

describe('aksApiAuthorizedIpRanges', function() {
    describe('run', function() {
        it('should give passing result if no managed clusters', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Kubernetes clusters found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(null,[]);
            aksApiAuthorizedIpRanges.run(cache, {}, callback);
        });

        it('should give Unknown result if unable to query AKS', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Kubernetes clusters');
                expect(results[0].region).to.equal('eastus');
                done();
            };
            const cache = createCache(null,null);
            aksApiAuthorizedIpRanges.run(cache, {}, callback);
        })

        it('should give failing result if Kubernetes Service does not have authorized IP ranges configured for secure access to API server', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('AKS cluster does not have authorized IP ranges configured for secure access to API server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(null,[listCluster[1]]);
            aksApiAuthorizedIpRanges.run(cache, {}, callback);
        });

        it('should give passing result if Kubernetes Service has authorized IP ranges configured for secure access to API server', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('AKS cluster has authorized IP ranges configured for secure access to API server');
                expect(results[0].region).to.equal('eastus');
                done();
            };
            const cache = createCache(null,[listCluster[0]]);
            aksApiAuthorizedIpRanges.run(cache, {}, callback);
        });
    });
});