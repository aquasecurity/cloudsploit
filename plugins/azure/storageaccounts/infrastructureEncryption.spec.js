var expect = require('chai').expect;
var infrastructureEncryptionEnabled = require('./infrastructureEncryption');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
        'tags': { 'key': 'value' },
        'encryption': {
             "requireInfrastructureEncryption": true,
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
        'tags': {},
        'encryption': {
            "services": {}
        }
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

describe('infrastructureEncryptionEnabled', function() {
    describe('run', function() {
        it('should give passing result if no storage accounts', function(done) {
            const cache = createCache([]);
            infrastructureEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function(done) {
            const cache = createErrorCache();
            infrastructureEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Storage Accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if infrastructure encryption enabled', function(done) {
            const cache = createCache([storageAccounts[0]]);
            infrastructureEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Storage Account has infrastructure encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if infrastructure encryption not enabled', function(done) {
            const cache = createCache([storageAccounts[1]]);
            infrastructureEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage Account does not have infrastructure encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});