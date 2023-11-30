var expect = require('chai').expect;
var namespaceEncryptionAtRest = require('./namespaceEncryptionAtRest.js');

const namespaces = [
    {
        sku: { name: 'Premium', tier: 'Premium', capacity: 1 },
        id: '/subscriptions/234/myrg/providers/Microsoft.ServiceBus/namespaces/test',
        name: 'test',
        type: 'Microsoft.ServiceBus/Namespaces',
        location: 'East US',
        publicNetworkAccess: 'Enabled',
        disableLocalAuth: false,
        provisioningState: 'Succeeded',
        status: 'Active'
    },
    {
        sku: { name: 'Premium', tier: 'Premium', capacity: 1 },
        id: '/subscriptions/234/myrg/providers/Microsoft.ServiceBus/namespaces/test2',
        name: 'test2',
        type: 'Microsoft.ServiceBus/Namespaces',
        location: 'East US',
        publicNetworkAccess: 'Enabled',
        disableLocalAuth: true,
        provisioningState: 'Succeeded',
        status: 'Active',
        encryption: {
            keySource: 'Microsoft.KeyVault',
            requireInfrastructureEncryption: false
          },
    },
    {
        sku: { name: 'Basic', tier: 'Basic' },
        id: '/subscriptions/234/myrg/providers/Microsoft.ServiceBus/namespaces/test3',
        name: 'test2',
        type: 'Microsoft.ServiceBus/Namespaces',
        location: 'East US',
        publicNetworkAccess: 'Enabled',
        disableLocalAuth: true,
        provisioningState: 'Succeeded',
        status: 'Active'
    },
];


const createCache = (namespaces, err) => {

    return {
        serviceBus: {
            listNamespacesBySubscription: {
                'eastus': {
                    data: namespaces,
                    err: err
                }
            }
        }
    };
};

describe('namespaceEncryptionAtRest', function () {
    describe('run', function () {

        it('should give a passing result if no Service Bus namespaces are found', function (done) {
            const cache = createCache([], null);
            namespaceEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Service Bus namespaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Service Bus namespaces', function (done) {
            const cache = createCache(null, ['error']);
            namespaceEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Service Bus namespaces');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    
        it('should give passing result if namespace is not using premium tier', function (done) {
            const cache = createCache([namespaces[2]], null);
            namespaceEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Service Bus Namespace is not a premium namespace');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if namespace is using CMK encryption', function (done) {
            const cache = createCache([namespaces[1]], null);
            namespaceEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Service Bus Namespace is encrypted using CMK');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if namespace is not using CMK encryption', function (done) {
            const cache = createCache([namespaces[0]], null);
            namespaceEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Service Bus Namespace is not encrypted using CMK');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});