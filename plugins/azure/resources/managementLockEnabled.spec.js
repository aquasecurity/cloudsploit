var expect = require('chai').expect;
var managementLockEnabled = require('./managementLockEnabled');

const resourceId = '/subscriptions/123/resourceGroups/testrg/providers/Microsoft.Compute/virtualMachines/testvm';
const lockIdCanNotDelete = '/subscriptions/123/resourceGroups/testrg/providers/Microsoft.Compute/virtualMachines/testvm/providers/Microsoft.Authorization/locks/testlock';
const lockIdReadOnly = '/subscriptions/123/resourceGroups/testrg/providers/Microsoft.Compute/virtualMachines/testvm2/providers/Microsoft.Authorization/locks/testlock2';
const lockIdBadLevel = '/subscriptions/123/resourceGroups/testrg/providers/Microsoft.Compute/virtualMachines/testvm3/providers/Microsoft.Authorization/locks/testlock3';

const resources = [
    {
        id: resourceId,
        name: 'testvm',
        type: 'Microsoft.Compute/virtualMachines',
        location: 'eastus',
        tags: { cloudsploitLock: 'true' }
    },
    {
        id: '/subscriptions/123/resourceGroups/testrg/providers/Microsoft.Compute/virtualMachines/testvm2',
        name: 'testvm2',
        type: 'Microsoft.Compute/virtualMachines',
        location: 'eastus',
        tags: { cloudsploitLock: 'true' }
    },
    {
        id: '/subscriptions/123/resourceGroups/testrg/providers/Microsoft.Compute/virtualMachines/testvm3',
        name: 'testvm3',
        type: 'Microsoft.Compute/virtualMachines',
        location: 'eastus',
        tags: { cloudsploitLock: 'true' }
    },
    {
        id: '/subscriptions/123/resourceGroups/testrg/providers/Microsoft.Compute/virtualMachines/testvm-no-tag',
        name: 'testvm-no-tag',
        type: 'Microsoft.Compute/virtualMachines',
        location: 'eastus',
        tags: {}
    }
];

const locks = [
    {
        id: lockIdCanNotDelete,
        name: 'testlock',
        properties: { level: 'CanNotDelete' }
    },
    {
        id: lockIdReadOnly,
        name: 'testlock2',
        properties: { level: 'ReadOnly' }
    },
    {
        id: lockIdBadLevel,
        name: 'testlock3',
        properties: { level: 'Unknown' }
    }
];

const createCache = (resourceData, lockData) => {
    return {
        resources: {
            list: { eastus: { data: resourceData || [] } }
        },
        managementLocks: {
            listAtSubscriptionLevel: { global: { data: lockData || [] } }
        }
    };
};

const createErrorCache = () => ({
    resources: { list: { eastus: { err: 'error', data: null } } },
    managementLocks: { listAtSubscriptionLevel: { global: { err: 'error', data: null } } }
});

describe('managementLockEnabled', function() {
    describe('run', function() {

        it('should give passing result if no management locks exist', function(done) {
            const cache = createCache([], []);
            managementLockEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Management Locks');
                done();
            });
        });

        it('should give unknown result if unable to query management locks', function(done) {
            const cache = createErrorCache();
            managementLockEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.be.at.least(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should pass if tagged resource has a CanNotDelete lock', function(done) {
            const cache = createCache([resources[0]], [locks[0]]);
            managementLockEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('CanNotDelete');
                done();
            });
        });

        it('should pass if tagged resource has a ReadOnly lock', function(done) {
            const cache = createCache([resources[1]], [locks[1]]);
            managementLockEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('ReadOnly');
                done();
            });
        });

        it('should fail if tagged resource has no lock', function(done) {
            const cache = createCache([resources[0]], []);
            managementLockEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have Management Lock');
                done();
            });
        });

        it('should fail if tagged resource has a lock with invalid level', function(done) {
            const cache = createCache([resources[2]], [locks[2]]);
            managementLockEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('is not CanNotDelete or ReadOnly');
                done();
            });
        });

        it('should give passing result if no resources are tagged for lock verification', function(done) {
            const cache = createCache([resources[3]], [locks[0]]);
            managementLockEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    });
});
