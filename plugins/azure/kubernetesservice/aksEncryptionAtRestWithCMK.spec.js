var expect = require('chai').expect;
var aksEncryptionAtRestWithCMK = require('./aksEncryptionAtRestWithCMK');

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
        "diskEncryptionSetID" : '/path/to/resource'
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

describe('aksEncryptionAtRestWithCMK', function() {
    describe('run', function() {
        it('should give passing result if no clusters', function(done) {
            const cache = createCache([]);
            aksEncryptionAtRestWithCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Kubernetes clusters');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if kubernetes cluster data is not encrypted using CMK', function(done) {
            const cache = createCache([managedClusters[0]]);
            aksEncryptionAtRestWithCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('AKS cluster data is not encrypted using CMK');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for kubernetes clusters', function(done) {
            const cache = createErrorCache();
            aksEncryptionAtRestWithCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Kubernetes clusters: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if kubernetes cluster data is encrypted using CMK', function(done) {
            const cache = createCache([managedClusters[1]]);
            aksEncryptionAtRestWithCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('AKS cluster data is encrypted using CMK');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});