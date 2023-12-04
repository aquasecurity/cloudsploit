var expect = require('chai').expect;
var queueServiceAllAccessAcl = require('./queueServiceAllAccessAcl');

const storageAccounts = [
    {
        sku: [Object],
        kind: 'StorageV2',
        id: '/subscriptions/1234/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Storage/storageAccounts/csb100320011e293683',
        name: 'csb100320011e293683',
        type: 'Microsoft.Storage/storageAccounts',
        location: 'eastus',
        tags: [Object],
        privateEndpointConnections: [],
        minimumTlsVersion: 'TLS1_2',
        allowBlobPublicAccess: false,
        networkAcls: [Object],
        supportsHttpsTrafficOnly: true,
        encryption: [Object],
        accessTier: 'Hot',
        provisioningState: 'Succeeded',
        creationTime: '2021-03-09T16:54:18.2838672Z',
        primaryEndpoints: [Object],
        primaryLocation: 'eastus',
        statusOfPrimary: 'available'
    }
];

const listKeys = [
    {
        keyName: 'key1',
        value: 'r0jtlC8ninZ0d8/Wn1DSu+YyROFiddLAVHROGtKuj1RHaaExE9DcWDQFdcy4NG8Xd0ecJuW17P15+ASth3mIhg==',
        permissions: 'FULL'
    },
    {
        keyName: 'key2',
        value: 'r0jtlC8ninZ0d8/Wn1DSu+YyROFiddLAVHROGtKuj1RHaaExE9DcWDQFdcy4NG8Xd0ecJuW17P15+ASth3mIhg==',
        permissions: 'FULL'
    },
];

const listQueuesSegmented = [
    {
        "name": "queuecs"
    }
];

const getQueueAcl = [
    {
        name: 'queuecs',
        signedIdentifiers: [{ accessPolicy: { permissions: 'raup' } }]
    },
    {
        name: 'queuecs',
        signedIdentifiers: {}
    },
    {
        name: 'queuecs',
        signedIdentifiers: [{ accessPolicy: { permissions: 'cwdl' } }]
    },
];

const createCache = (list, listKeys, segments, acl, keysErr) => {
    var id = (list && list.length) ? list[0].id : null;
    var segmentName = (segments && segments.length) ? segments[0].name : null;
    return {
        storageAccounts: {
            list: {
                'eastus': {
                    data: list
                },
            },
            listKeys: {
                'eastus': {
                    [id]: {
                        err: keysErr,
                        data: listKeys
                    },
                },
            },
        },
        queueService: {
            listQueuesSegmented: {
                'eastus': {
                    [id]: {
                        data: segments     
                    }
                }
            },
            getQueueAcl: {
                'eastus': {
                    [id + '/queueService/' + segmentName]: {
                        data: acl
                    }
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        storageAccounts: {
            list: {
                'eastus': {
                    err: {
                        message: 'error while listing storageAccounts'
                    },
                },
            },
            listKeys: {
                'eastus': {
                    err: {
                        message: 'error while listing storageAccount keys'
                    },
                },
            },
        },
        queueService: {
            listQueuesSegmented: {
                'eastus': {
                    err: {
                        message: 'Unable to list queue Segments'
                    }
                }
            },
            getQueueAcl: {
                'eastus': {
                    err: {
                        message: 'Unable to get Queue Acl'
                    }
                }
            }
        }
    };
};

describe('queueServiceAllAccessAcl', function () {
    describe('run', function () {
        it('should PASS if Queue ACL does not contain full access permissions', function (done) { 
            const cache = createCache(storageAccounts[0], [listKeys[0]], [listQueuesSegmented[0]], [getQueueAcl[2]]);
            queueServiceAllAccessAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if Queue ACL has not been configured', function (done) {
            const cache = createCache(storageAccounts[0], [listKeys[0]], [listQueuesSegmented[0]], getQueueAcl[1]);
            queueServiceAllAccessAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should FAIL if Queue ACL allows', function (done) {
            const cache = createCache([storageAccounts[0]], [listKeys[0]], [listQueuesSegmented[0]], getQueueAcl[0]);
            queueServiceAllAccessAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should PASS if No storage accounts found', function (done) {
            const cache = createCache([]);
            queueServiceAllAccessAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if Unable to query for for storage accounts', function (done) {
            const cache = createErrorCache();
            queueServiceAllAccessAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if Unable to query for for Queue Service using Storage Account SAS', function (done) {
            const cache = createErrorCache();
            queueServiceAllAccessAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if Unable to query for for Queue Service', function (done) {
            const cache = createErrorCache();
            queueServiceAllAccessAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});

