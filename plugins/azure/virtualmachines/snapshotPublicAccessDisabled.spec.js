var expect = require('chai').expect;
var snapshotPublicAccessDisabled = require('./snapshotPublicAccessDisabled');

const disks = [
    {
        'name': 'test',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/snapshot/test',
        'type': 'Microsoft.Compute/disks',
        'location': 'eastus',
        'encryption': {
            'type': 'EncryptionAtRestWithPlatformKey'
        },
        "networkAccessPolicy": 'allowall'
    },
    {
        'name': 'test',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/snapshot/test',
        'type': 'Microsoft.Compute/disks',
        'location': 'eastus',
        'encryption': {
            'type': 'EncryptionAtRestWithCustomerKey',
            'diskEncryptionSetId': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/diskEncryptionSets/test-encrypt-set'
        },
        "networkAccessPolicy": 'DenyAll'
    },
    {
        'name': 'test',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/snapshot/test',
        'type': 'Microsoft.Compute/disks',
        'location': 'eastus',
        'encryption': {
            'type': 'EncryptionAtRestWithPlatformAndCustomerKeys',
            'diskEncryptionSetId': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/diskEncryptionSets/test-encrypt-set'
        },
        "networkAccessPolicy": 'AllowPrivate' 
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

describe('snapshotPublicAccessDisabled', function() {
    describe('run', function() {
        it('should give passing result if no disk snapshot found', function(done) {
            const cache = createCache([]);
            snapshotPublicAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No VM disk snapshots found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for disk snapshot', function(done) {
            const cache = createCache();
            snapshotPublicAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for VM disk snapshots:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Disk snapshot has private access only', function(done) {
            const cache = createCache([disks[1]]);
            snapshotPublicAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VM disk snapshot has public access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Disk snapshot not have public access disabled', function(done) {
            const cache = createCache([disks[0]]);
            snapshotPublicAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('VM disk snapshot does not have public access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});