var expect = require('chai').expect;
var tableServiceAllAccessAcl = require('./tableServiceAllAccessAcl');

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

const listTablesSegmented = [
    {
        "name": "testtablecs"
    }
];

const getTableAcl = [
    {
        name: 'testtablecs',
        signedIdentifiers: [{ accessPolicy: { permission: 'raup' } }]
    },
    {
        name: 'testtablecs ',
        signedIdentifiers: {}
    },
    {
        name: 'testtablecs ',
        signedIdentifiers: [{ accessPolicy: { permission: 'cwdl' } }]
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
        tableService: {
            listTablesSegmented: {
                'eastus': {
                    [id]: {
                        data: segments     
                    }
                }
            },
            getTableAcl: {
                'eastus': {
                    [id + '/tableService/' + segmentName]: {
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
        tableService: {
            listTablesSegmented: {
                'eastus': {
                    err: {
                        message: 'Unable to list file share'
                    }
                }
            },
            getTableAcl: {
                'eastus': {
                    err: {
                        message: 'Unable to get share Acl'
                    }
                }
            }
        }
    };
};

describe('tableServiceAllAccessAcl', function () {
    describe('run', function () {
        it('should PASS if Table ACL does not contain full access permissions', function (done) { 
            const cache = createCache(storageAccounts[0], [listKeys[0]], [listTablesSegmented[0]], [getTableAcl[2]]);
            tableServiceAllAccessAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if Table ACL has not been configured', function (done) {
            const cache = createCache(storageAccounts[0], [listKeys[0]], [listTablesSegmented[0]], getTableAcl[1]);
            tableServiceAllAccessAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should FAIL if Table ACL allows', function (done) {
            const cache = createCache([storageAccounts[0]], [listKeys[0]], [listTablesSegmented[0]], getTableAcl[2]);
            tableServiceAllAccessAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should PASS if No storage accounts found', function (done) {
            const cache = createCache([]);
            tableServiceAllAccessAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if Unable to query for storage accounts', function (done) {
            const cache = createErrorCache();
            tableServiceAllAccessAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if Unable to query for for Table Service using Storage Account SAS', function (done) {
            const cache = createErrorCache();
            tableServiceAllAccessAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if Unable to query Table Service table ACL', function (done) {
            const cache = createErrorCache();
            tableServiceAllAccessAcl.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});