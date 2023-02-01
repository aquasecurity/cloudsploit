var expect = require('chai').expect;
var snapshotByokEncryptionEnabled = require('./snapshotByokEncryptionEnabled');

const disks = [
    {
        'name': 'test',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/snapshot/test',
        'type': 'Microsoft.Compute/disks',
        'location': 'eastus',
        'encryption': {
            'type': 'EncryptionAtRestWithPlatformKey'
        }
    },
    {
        'name': 'test',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/snapshot/test',
        'type': 'Microsoft.Compute/disks',
        'location': 'eastus',
        'encryption': {
            'type': 'EncryptionAtRestWithCustomerKey',
            'diskEncryptionSetId': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/diskEncryptionSets/test-encrypt-set'
        }
    },
    {
        'name': 'test',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/snapshot/test',
        'type': 'Microsoft.Compute/disks',
        'location': 'eastus',
        'encryption': {
            'type': 'EncryptionAtRestWithPlatformAndCustomerKeys',
            'diskEncryptionSetId': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/diskEncryptionSets/test-encrypt-set'
        }
    }
];

const createCache = (snapshots) => {
    const snap = {};
    if (snapshots) {
        snap['data'] = snapshots;
    }
    return {
        snapshots: {
            list: {
                'eastus': snap
            }
        }
    };
};

describe('snapshotByokEncryptionEnabled', function() {
    describe('run', function() {
        it('should give passing result if no disk snapshot found', function(done) {
            const cache = createCache([]);
            snapshotByokEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No virtual machine disk snapshots found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for disk snapshot', function(done) {
            const cache = createCache();
            snapshotByokEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machine disk snapshots:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Disk snapshot has BYOK encryption enabled only', function(done) {
            const cache = createCache([disks[1]]);
            snapshotByokEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VM disk snapshot has BYOK encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Disk snapshot has BYOK encryption enabled along with platform key ', function(done) {
            const cache = createCache([disks[2]]);
            snapshotByokEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VM disk snapshot has BYOK encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Disk snapshot has BYOK encryption disabled', function(done) {
            const cache = createCache([disks[0]]);
            snapshotByokEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('VM disk snapshot does not have BYOK encryption enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});