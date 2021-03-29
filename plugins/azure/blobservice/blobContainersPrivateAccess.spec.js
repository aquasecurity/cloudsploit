var expect = require('chai').expect;
var blobPrivateAccess = require('./blobContainersPrivateAccess');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
    }
];

const blobContainers = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/blobServices/default/containers/container1',
        'location': 'eastus',
        'name': 'container1',
        'publicAccess' : 'None'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/blobServices/default/containers/container1',
        'location': 'eastus',
        'name': 'container1',
        'publicAccess' : 'Container'
    }
];

const createCache = (storageAccounts, blobContainers) => {
    let conatiners = {};
    if (storageAccounts.length) {
        conatiners[storageAccounts[0].id] = {
            data : blobContainers
        };
    }
    return {
        storageAccounts: {
            list: {
                'eastus': {
                    data: storageAccounts
                }
            }
        },
        blobContainers: {
            list: {
                'eastus': conatiners
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key == 'storageAccount') {
        return {
            storageAccounts: {
                list: {
                    'eastus': {}
                }
            }
        };
    } else {
        return {
            storageAccounts: {
                list: {
                    'eastus': {
                        data: [storageAccounts[0]]
                    }
                }
            },
            blobContainers: {
                list: {
                    'eastus': {}
                }
            }
        };
    }
};

describe('blobContainerPrivateAccess', function() {
    describe('run', function() {
        it('should give passing result if no storage accounts', function(done) {
            const cache = createCache([], []);
            blobPrivateAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Storage Accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no blob containers', function(done) {
            const cache = createCache([storageAccounts[0]], []);
            blobPrivateAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage Account does not contain blob containers');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function(done) {
            const cache = createErrorCache('storageAccount');
            blobPrivateAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Storage Accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for blob containers', function(done) {
            const cache = createErrorCache('blobContainer');
            blobPrivateAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Blob Containers');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if blob container does not allow public access', function(done) {
            const cache = createCache([storageAccounts[0]], [blobContainers[0]]);
            blobPrivateAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Blob container does not allow public access');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if blob container allows public access', function(done) {
            const cache = createCache([storageAccounts[0]], [blobContainers[1]]);
            blobPrivateAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Blob container allows public access');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 