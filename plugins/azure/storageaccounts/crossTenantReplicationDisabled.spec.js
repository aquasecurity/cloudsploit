var expect = require('chai').expect;
var crossTenantReplicationDisabled = require('./crossTenantReplicationDisabled');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus',
        'allowCrossTenantReplication': false
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus',
        'allowCrossTenantReplication': true
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus'
    }
];

const createCache = (storageAccounts) => {
    return {
        storageAccounts: {
            list: {
                'eastus': {
                    data: storageAccounts
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        storageAccounts: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('crossTenantReplicationDisabled', function () {
    describe('run', function () {
        it('should give passing result if no storage accounts found', function (done) {
            const cache = createCache([]);
            crossTenantReplicationDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function (done) {
            const cache = createErrorCache();
            crossTenantReplicationDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if cross tenant replication is disabled', function (done) {
            const cache = createCache([storageAccounts[0]]);
            crossTenantReplicationDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has cross tenant replication disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if cross tenant replication is enabled', function (done) {
            const cache = createCache([storageAccounts[1]]);
            crossTenantReplicationDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('has cross tenant replication enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if allowCrossTenantReplication is not set', function (done) {
            const cache = createCache([storageAccounts[2]]);
            crossTenantReplicationDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has cross tenant replication disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
