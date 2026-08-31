var expect = require('chai').expect;
var fileShareSmbProtocolVersion = require('./fileShareSmbProtocolVersion');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'name': 'acc',
        'type': 'Microsoft.Storage/storageAccounts',
        'location': 'eastus'
    }
];

const fileServiceProperties = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/fileServices/default',
        'protocolSettings': {
            'smb': {
                'versions': 'SMB3.1.1;'
            }
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/fileServices/default',
        'protocolSettings': {
            'smb': {
                'versions': 'SMB2.1;SMB3.0;SMB3.1.1;'
            }
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/fileServices/default',
        'protocolSettings': {
            'smb': {}
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/fileServices/default'
    }
];

const createCache = (storageAccounts, serviceProperties, servicePropertiesErr) => {
    const accountId = storageAccounts && storageAccounts.length ? storageAccounts[0].id : null;
    const propsObj = {};
    if (accountId) {
        if (servicePropertiesErr) {
            propsObj[accountId] = { err: servicePropertiesErr };
        } else if (serviceProperties) {
            propsObj[accountId] = { data: serviceProperties };
        }
    }
    return {
        storageAccounts: {
            list: {
                'eastus': {
                    data: storageAccounts
                }
            }
        },
        fileServices: {
            getServiceProperties: {
                'eastus': propsObj
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

describe('fileShareSmbProtocolVersion', function () {
    describe('run', function () {
        it('should give passing result if no storage accounts found', function (done) {
            const cache = createCache([], null);
            fileShareSmbProtocolVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function (done) {
            const cache = createErrorCache();
            fileShareSmbProtocolVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to get file service properties', function (done) {
            const cache = createCache(storageAccounts, null, ['Forbidden']);
            fileShareSmbProtocolVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to get file service properties');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if only SMB3.1.1 is allowed', function (done) {
            const cache = createCache(storageAccounts, fileServiceProperties[0]);
            fileShareSmbProtocolVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('File share SMB protocol version is set to SMB3.1.1');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if older SMB versions are also allowed', function (done) {
            const cache = createCache(storageAccounts, fileServiceProperties[1]);
            fileShareSmbProtocolVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SMB2.1, SMB3.0, SMB3.1.1 instead of SMB3.1.1 only');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no SMB versions are configured', function (done) {
            const cache = createCache(storageAccounts, fileServiceProperties[2]);
            fileShareSmbProtocolVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('all SMB versions instead of SMB3.1.1 only');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if protocol settings are not present', function (done) {
            const cache = createCache(storageAccounts, fileServiceProperties[3]);
            fileShareSmbProtocolVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('all SMB versions instead of SMB3.1.1 only');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
