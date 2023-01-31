var expect = require('chai').expect;
var diskUnattachedAndDefaultEncryption = require('./diskUnattachedAndDefaultEncryption');

const disks = [
    {
        'name': 'test',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/disks/test',
        'type': 'Microsoft.Compute/disks',
        'location': 'eastus',
        'encryption': {
            'type': 'EncryptionAtRestWithCustomerKey'
        },
        'diskState': 'Reserved'
    },
    {
        'name': 'test',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/disks/test',
        'type': 'Microsoft.Compute/disks',
        'location': 'eastus',
        'encryption': {
            'type': 'EncryptionAtRestWithPlatformKey',
            'diskEncryptionSetId': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/diskEncryptionSets/test-encrypt-set'
        },
        'diskState': 'unattached'
    }
];

const createCache = (disks) => {
    const disk = {};
    if (disks) {
        disk['data'] = disks;
    }
    return {
        disks: {
            list: {
                'eastus': disk
            }
        }
    };
};

describe('diskUnattachedAndDefaultEncryption', function() {
    describe('run', function() {
        it('should give passing result if no disk volumes found', function(done) {
            const cache = createCache([]);
            diskUnattachedAndDefaultEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing disk volumes found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for disk volumes', function(done) {
            const cache = createCache();
            diskUnattachedAndDefaultEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machine disk volumes');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Disk volume has default enabled only and is in unattached state', function(done) {
            const cache = createCache([disks[1]]);
            diskUnattachedAndDefaultEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Disk volume is unattached and encrypted with default encryption key');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Disk volume has is attached or default encryption not enabled', function(done) {
            const cache = createCache([disks[0]]);
            diskUnattachedAndDefaultEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Disk volume is not unattached and encrypted with default encryption key');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});