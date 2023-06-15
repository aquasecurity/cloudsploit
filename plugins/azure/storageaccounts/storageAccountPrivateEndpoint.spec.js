var expect = require('chai').expect;
var storageAccountPrivateEndpoint = require('./storageAccountPrivateEndpoint');

const storageAccounts = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
        'tags': { 'key': 'value' },
        "privateEndpointConnections": [

            {
                "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc/privateEndpointConnections/test.3d321801-7cb1-4586-afa7-deee7ab88744",
                "name": "test.3d321801-7cb1-4586-afa7-deee7ab88744",
                "type": "Microsoft.Storage/storageAccounts/privateEndpointConnections",
            }
        ],
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Storage/storageAccounts/acc',
        'location': 'eastus',
        'name': 'acc',
        'tags': {},
        "privateEndpointConnections": []
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

describe('storageAccountPrivateEndpoint', function() {
    describe('run', function() {
        it('should give passing result if no storage accounts', function(done) {
            const cache = createCache([]);
            storageAccountPrivateEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for storage accounts', function(done) {
            const cache = createErrorCache();
            storageAccountPrivateEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Storage Accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if private endpoint configured', function(done) {
            const cache = createCache([storageAccounts[0]]);
            storageAccountPrivateEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Private endpoints are configured for the storage account');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no private endpoint', function(done) {
            const cache = createCache([storageAccounts[1]]);
            storageAccountPrivateEndpoint.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Private endpoints are not configured for the storage account');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});