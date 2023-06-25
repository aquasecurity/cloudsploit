var expect = require('chai').expect;
var queueServiceLoggingEnabled = require('./queueServiceLoggingEnabled');

const storageAccounts = [
    {
        kind: 'StorageV2',
        id: '/subscriptions/1234/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Storage/storageAccounts/csb100320011e293683',
        name: 'csb100320011e293683',
        type: 'Microsoft.Storage/storageAccounts',
        location: 'eastus',
        privateEndpointConnections: [],
        minimumTlsVersion: 'TLS1_2',
        allowBlobPublicAccess: false,
        supportsHttpsTrafficOnly: true,
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
    }
];

const getProperties = [
    {
        queueAnalyticsLogging: {
            version: '1.0',
            read: false,
            write: false,
            retentionPolicy: { enabled: false, days: undefined }
        },
    },
    {
        queueAnalyticsLogging: {
            version: '1.0',
            deleteProperty: true,
            read: true,
            write: true,
            retentionPolicy: { enabled: false, days: undefined }
        },
    }
];


const createCache = (list, listKeys, segments, acl, keysErr) => {
    var id = (list && list.length) ? list[0].id : null;
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
            getProperties: {
                'eastus': {
                    [id]: {
                        data: segments     
                    }
                }
            }
        }
    };
};

// const createErrorCache = () => {
//     return {
//         storageAccounts: {
//             list: {
//                 'eastus': {
//                     err: {
//                         message: 'error while listing storageAccounts'
//                     },
//                 },
//             },
//             listKeys: {
//                 'eastus': {
//                     err: {
//                         message: 'error while listing storageAccount keys'
//                     },
//                 },
//             },
//         },
//         queueService: {
//             listQueuesSegmented: {
//                 'eastus': {
//                     err: {
//                         message: 'Unable to list queue Segments'
//                     }
//                 }
//             },
//             getQueueAcl: {
//                 'eastus': {
//                     err: {
//                         message: 'Unable to get Queue Acl'
//                     }
//                 }
//             }
//         }
//     };
// };

describe('queueServiceLoggingEnabled', function () {
    describe('run', function () {
        it('should PASS if Queue Service has logging enabled', function (done) { 
            const cache = createCache([storageAccounts[0]], [listKeys[0]], getProperties[1]);
            queueServiceLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('Queue Service has logging enabled for read, write and delete requests');
                done();
            });
        });

        it('should PASS if Queue Service does not have logging enabled', function (done) {
            const cache = createCache([storageAccounts[0]], [listKeys[0]], getProperties[0]);
            queueServiceLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('eastus');
                expect(results[0].message).to.equal('Queue Service does not have logging enabled for read, write and delete requests');
                done();
            });
        });

        it('should PASS if no storage account found', function (done) {
            const cache = createCache([], [listKeys[0]], []);
            queueServiceLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('eastus');
                expect(results[0].message).to.equal('No storage accounts found');

                done();
            });
        });

        it('should UNKNOWN if Unable to query for for storage accounts', function (done) {
            const cache = createCache(null)
            queueServiceLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts:');
                done();
            });
        });


        it('should UNKNOWN if Unable to query for for Queue Service', function (done) {
            const cache = createCache([storageAccounts[0]], [listKeys[0]], null);
            queueServiceLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Queue Service:');
                done();
            });
        });
    });
});

