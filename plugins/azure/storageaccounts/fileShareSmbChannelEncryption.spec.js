var expect = require('chai').expect;
var fileShareSmbChannelEncryption = require('./fileShareSmbChannelEncryption');

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
                'channelEncryption': 'AES-256-GCM;'
            }
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/fileServices/default',
        'protocolSettings': {
            'smb': {
                'channelEncryption': 'AES-128-CCM;AES-128-GCM;AES-256-GCM;'
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

describe('fileShareSmbChannelEncryption', function () {
    describe('run', function () {
        it('should give passing result if no storage accounts found', function (done) {
            const cache = createCache([], null);
            fileShareSmbChannelEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function (done) {
            const cache = createErrorCache();
            fileShareSmbChannelEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for storage accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to get file service properties', function (done) {
            const cache = createCache(storageAccounts, null, ['Forbidden']);
            fileShareSmbChannelEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to get file service properties');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if only AES-256-GCM is allowed', function (done) {
            const cache = createCache(storageAccounts, fileServiceProperties[0]);
            fileShareSmbChannelEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('File share SMB channel encryption is set to AES-256-GCM');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if weaker channel encryption algorithms are also allowed', function (done) {
            const cache = createCache(storageAccounts, fileServiceProperties[1]);
            fileShareSmbChannelEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('AES-128-CCM, AES-128-GCM, AES-256-GCM instead of AES-256-GCM only');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no channel encryption algorithms are configured', function (done) {
            const cache = createCache(storageAccounts, fileServiceProperties[2]);
            fileShareSmbChannelEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('all SMB channel encryption algorithms instead of AES-256-GCM only');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if protocol settings are not present', function (done) {
            const cache = createCache(storageAccounts, fileServiceProperties[3]);
            fileShareSmbChannelEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('all SMB channel encryption algorithms instead of AES-256-GCM only');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
