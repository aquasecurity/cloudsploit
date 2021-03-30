var expect = require('chai').expect;
var blobSoftDeletionEnabled = require('./blobSoftDeletionEnabled');

const storageAccounts = [
    {
        "id": "/subscriptions/123/resourceGroups/test-group/providers/Microsoft.Storage/storageAccounts/test-account"
    }
];

const getServiceProperties = [
    {
        "sku": { "name": "Standard_LRS", "tier": "Standard" },
        "id": "/subscriptions/123/resourceGroups/test-group/providers/Microsoft.Storage/storageAccounts/test-account/blobServices/default",
        "name": "default",
        "type": "Microsoft.Storage/storageAccounts/blobServices",
        "cors": { "corsRules": [] },
        "deleteRetentionPolicy": { "enabled": true, "days": 30 }
    },
    {
        "sku": { "name": "Standard_LRS", "tier": "Standard" },
        "id": "/subscriptions/123/resourceGroups/test-group/providers/Microsoft.Storage/storageAccounts/csb100320011cd09016/blobServices/default",
        "name": "default",
        "type": "Microsoft.Storage/storageAccounts/blobServices",
        "cors": { "corsRules": [] },
        "deleteRetentionPolicy": { "enabled": false }
    }
];


const createCache = (list, err, getProperties, geterr) => {
    const id = (list && list.length) ? list[0].id : null;
    return {
        storageAccounts: {
            list: {
                'eastus': {
                    err: err,
                    data: list
                }
            }
        },
        blobServices: {
            getServiceProperties: {
                'eastus': {
                    [id]: {
                        err: geterr,
                        data: getProperties
                    }
                }
            }
        }
    }
};

describe('blobSoftDeletionEnabled', function() {
    describe('run', function() {
        it('should give passing result if no Storage Accounts', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                []
            );

            blobSoftDeletionEnabled.run(cache, {}, callback);
        })

        it('should give failing result if Blobs soft delete feature is not enabled for Storage Account', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Blobs soft delete feature is not enabled for Storage Account');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                storageAccounts,
                null,
                getServiceProperties[1]
            );

            blobSoftDeletionEnabled.run(cache, {}, callback);
        });

        it('should give failing result if Blobs deletion policy is configured to persist deleted blobs for less days than desired limit', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Blobs deletion policy is configured to persist deleted blobs');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                storageAccounts,
                null,
                getServiceProperties[0]
            );

            blobSoftDeletionEnabled.run(cache, { keep_deleted_blobs_for_days: '50' }, callback);
        });

        it('should give passing result if Blobs deletion policy is configured to persist deleted blobs for more days than desired limit', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Blobs deletion policy is configured to persist deleted blobs');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                storageAccounts,
                null,
                getServiceProperties[0]
            );

            blobSoftDeletionEnabled.run(cache, { keep_deleted_blobs_for_days: '20' }, callback);
        });

        it('should give unknown result if unable to query for Storage Accounts', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                storageAccounts,
                { message: "Unable to list Storage Accounts" },
            );

            blobSoftDeletionEnabled.run(cache, {}, callback);
        });
    })
})