var expect = require('chai').expect;
var namespaceLocalAuth = require('./namespaceLocalAuth.js');

const namespaces = [
    {
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
        id: '/subscriptions/234/myrg/providers/Microsoft.ServiceBus/namespaces/test',
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

describe('namespaceLocalAuth', function () {
    describe('run', function () {

        it('should give a passing result if no Service Bus namespaces are found', function (done) {
            const cache = createCache([], null);
            namespaceLocalAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Service Bus namespaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Service Bus namespaces', function (done) {
            const cache = createCache(null, ['error']);
            namespaceLocalAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Service Bus namespaces');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    
        it('should give passing result if local authenication is disabled for namespace', function (done) {
            const cache = createCache([namespaces[1]], null);
            namespaceLocalAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Service Bus Namespace has local authentication disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if local authentication is enabled for namespace', function (done) {
            const cache = createCache([namespaces[0]], null);
            namespaceLocalAuth.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Service Bus Namespace has local authentication enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});