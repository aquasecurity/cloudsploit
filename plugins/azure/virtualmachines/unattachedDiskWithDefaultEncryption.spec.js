var expect = require('chai').expect;
var diskUnattachedAndDefaultEncryption = require('./unattachedDiskWithDefaultEncryption');

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
                expect(results[0].message).to.include('No existing VM disk volumes found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for disk volumes', function(done) {
            const cache = createCache();
            diskUnattachedAndDefaultEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for VM disk volumes');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Disk volume is unattached and encrypted with default encryption key', function(done) {
            const cache = createCache([disks[1]]);
            diskUnattachedAndDefaultEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Disk volume is unattached and encrypted with default encryption key');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Disk volume is attached or encrypted with BYO', function(done) {
            const cache = createCache([disks[0]]);
            diskUnattachedAndDefaultEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Disk volume is attached or encrypted with BYOK');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});