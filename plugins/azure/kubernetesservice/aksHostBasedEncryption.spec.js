var expect = require('chai').expect;
var aksHostBasedEncryption = require('./aksHostBasedEncryption');
const listCluster = [
    {
        "id": "/subscriptions/12345/resourcegroups/ABSBAKS2/providers/Microsoft.ContainerService/managedClusters/absbaks2",
        "location": "eastus",
        'tags': { 'key': 'value' },
        "name": "absbaks2",
        "type": "Microsoft.ContainerService/ManagedClusters",
        "sku": {
            "name": "Basic",
            "tier": "Free"
        },
        "agentPoolProfiles": [
            {
                "name": "agentpool",
                "osType": "Linux",
                "enableEncryptionAtHost": true,
            },
            {
                "name": "test",
                "osType": "Linux",
                "enableEncryptionAtHost": true,
            }
        ],
    },
    {
        "id": "/subscriptions/12345/resourcegroups/ABSBAKS2/providers/Microsoft.ContainerService/managedClusters/absbaks2",
        "location": "eastus",
        'tags': {},
        "name": "absbaks2",
        "type": "Microsoft.ContainerService/ManagedClusters",
        "sku": {
            "name": "Basic",
            "tier": "Free"
        },
        "agentPoolProfiles": [
            {
                "name": "agentpool",
                "mode": "System",
                "osType": "Linux",
                "enableEncryptionAtHost": true
            },
            {
                "name": "test",
                "provisioningState": "Succeeded",
                "orchestratorVersion": "1.17.9",
                "mode": "User",
                "osType": "Linux"
            }
        ],
    },
    {
        "id": "/subscriptions/12345/resourcegroups/ABSBAKS2/providers/Microsoft.ContainerService/managedClusters/absbaks2",
        "location": "eastus",
        'tags': {},
        "name": "absbaks2",
        "type": "Microsoft.ContainerService/ManagedClusters",
        "sku": {
            "name": "Basic",
            "tier": "Free"
        },
        "agentPoolProfiles": [
        ],
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

describe('aksHostBasedEncryption', function() {
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
            aksHostBasedEncryption.run(cache, {}, callback);
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
            aksHostBasedEncryption.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query node profile', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing node pools found');
                expect(results[0].region).to.equal('eastus');
                done();
            };
            const cache = createCache(null,[listCluster[2]]);
            aksHostBasedEncryption.run(cache, {}, callback);
        })


        it('should give failing result if Kubernetes Service node pools does not have encryption at host enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('AKS Cluster does not have encryption at host enabled for following node pools: test ');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(null,[listCluster[1]]);
            aksHostBasedEncryption.run(cache, {}, callback);
        });

        it('should give passing result if Kubernetes Service have encryption at host enabled for all node pools', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('AKS Cluster has encryption at host enabled for all node pools');
                expect(results[0].region).to.equal('eastus');
                done();
            };
            const cache = createCache(null,[listCluster[0]]);
            aksHostBasedEncryption.run(cache, {}, callback);
        });
    });
});