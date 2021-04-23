var expect = require('chai').expect;
var blobServiceImmutable = require('./blobServiceImmutable');

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
        'hasImmutabilityPolicy' : true
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/blobServices/default/containers/container1',
        'location': 'eastus',
        'name': 'container1',
        'hasImmutabilityPolicy' : false
    }
];

const blobServices = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/blobServices/default',
        'location': 'eastus',
        'name': 'default'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/blobServices/default',
        'location': 'eastus',
        'name': 'default',
        'deleteRetentionPolicy': {
            'enabled': true,
            'days': 30
        }
    }
];

const createCache = (storageAccounts, blobServices, blobContainers) => {
    let conatiners = {};
    let services = {};
    if (storageAccounts.length) {
        conatiners[storageAccounts[0].id] = {
            data : blobContainers
        };
        services[storageAccounts[0].id] = {
            data : blobServices
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
        },
        blobServices: {
            list:{
                'eastus': services
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
    } else if (key == 'blobService') {
        return {
            storageAccounts: {
                list: {
                    'eastus': {
                        data: [storageAccounts[0]]
                    }
                }
            },
            blobServices: {
                list:{
                    'eastus': {}
                }
            }
        };
    } else {
        let services = {};
        services[storageAccounts[0].id] = {
            data : [blobServices[0]]
        };
        return {
            storageAccounts: {
                list: {
                    'eastus': {
                        data: [storageAccounts[0]]
                    }
                }
            },
            blobServices: {
                list:{
                    'eastus': services
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

describe('blobServiceImmutable', function() {
    describe('run', function() {
        it('should give passing result if no storage accounts', function(done) {
            const cache = createCache([], [], []);
            blobServiceImmutable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Storage Accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no blob services', function(done) {
            const cache = createCache([storageAccounts[0]], [], []);
            blobServiceImmutable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage Account does not contain blob services');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no blob containers', function(done) {
            const cache = createCache([storageAccounts[0]], [blobServices[0]], []);
            blobServiceImmutable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage Account does not contain blob containers');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function(done) {
            const cache = createErrorCache('storageAccount');
            blobServiceImmutable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Storage Accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query blob services', function(done) {
            const cache = createErrorCache('blobService');
            blobServiceImmutable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Blob Services');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query blob containers', function(done) {
            const cache = createErrorCache('blobContainer');
            blobServiceImmutable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Blob Containers');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if immutability is configured for blob service', function(done) {
            const cache = createCache([storageAccounts[0]], [blobServices[1]], []);
            blobServiceImmutable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Immutability has been configured for the blob service');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if immutability is configured for blob container', function(done) {
            const cache = createCache([storageAccounts[0]], [blobServices[0]], [blobContainers[0]]);
            blobServiceImmutable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Immutability has been configured for the blob container');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if immutability is not configuredfor blob container', function(done) {
            const cache = createCache([storageAccounts[0]], [blobServices[0]], [blobContainers[1]]);
            blobServiceImmutable.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Immutability has not been configured for the blob container');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});