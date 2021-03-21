var expect = require('chai').expect;
var fileServiceIEncryption = require('./fileServiceEncryption');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
        'encryption': {
            'services': {
                'file': {
                    'enabled': true
                }
            }
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
        'encryption': {
            'services': {
                'blob': {
                    'enabled': false
                }
            }
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

describe('fileServiceIEncryption', function() {
    describe('run', function() {
        it('should give passing result if no storage accounts', function(done) {
            const cache = createCache([]);
            fileServiceIEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function(done) {
            const cache = createErrorCache();
            fileServiceIEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if file encryption is enabled', function(done) {
            const cache = createCache([storageAccounts[0]]);
            fileServiceIEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Encryption is enabled on the File Service');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if file encryption is not enabled', function(done) {
            const cache = createCache([storageAccounts[1]]);
            fileServiceIEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Encryption is disabled on the File Service');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});