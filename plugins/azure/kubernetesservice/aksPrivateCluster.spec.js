var expect = require('chai').expect;
var aksPrivateCluster = require('./aksPrivateCluster');

const managedClusters = [
    {
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.ContainerService/managedClusters/tes-cluster',
        "location": 'eastus',
        "name": 'tes-cluster',
        "type": 'Microsoft.ContainerService/ManagedClusters',
        "provisioningState": 'Succeeded',
        "kubernetesVersion": '1.18.14',
        "dnsPrefix": 'tes-cluster-dns',
        "fqdn": 'tes-cluster-dns-f7b98b1e.hcp.eastus.azmk8s.io',
        "enableRBAC": true,
        "maxAgentPools": 10,
        "apiServerAccessProfile" : { "enablePrivateCluster": false },
    },
    {
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.ContainerService/managedClusters/tes-cluster',
        "location": 'eastus',
        "name": 'tes-cluster',
        "type": 'Microsoft.ContainerService/ManagedClusters',
        "provisioningState": 'Succeeded',
        "kubernetesVersion": '1.18.14',
        "dnsPrefix": 'tes-cluster-dns',
        "fqdn": 'tes-cluster-dns-f7b98b1e.hcp.eastus.azmk8s.io',
        "enableRBAC": false,
        "maxAgentPools": 10,
        "apiServerAccessProfile" : { "enablePrivateCluster": true },
    }
];

const createCache = (managedClusters) => {
    return {
        managedClusters: {
            list: {
                'eastus': {
                    data: managedClusters
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        managedClusters: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('aksPrivateCluster', function() {
    describe('run', function() {
        it('should give passing result if no clusters', function(done) {
            const cache = createCache([]);
            aksPrivateCluster.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Kubernetes clusters');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if kubernetes clusters is not private', function(done) {
            const cache = createCache([managedClusters[0]]);
            aksPrivateCluster.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('AKS cluster is not private');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for kubernetes clusters', function(done) {
            const cache = createErrorCache();
            aksPrivateCluster.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Kubernetes clusters: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if kubernetes clusters is private', function(done) {
            const cache = createCache([managedClusters[1]]);
            aksPrivateCluster.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('AKS cluster is private');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});