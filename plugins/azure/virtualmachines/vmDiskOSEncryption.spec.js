var expect = require('chai').expect;
var vmDiskOSEncryption = require('./vmDiskOSEncryption');

const disks = [
    {
        'name': 'test-vm_disk1_8fa6d20523294d6d808958c906551aa5',
        'id': '/subscriptions/123/resourceGroups/AKHTAR-RG/providers/Microsoft.Compute/disks/test-vm_disk1_8fa6d20523294d6d808958c906551aa5',
        'type': 'Microsoft.Compute/disks',
        'encryption': {
            'type': 'EncryptionAtRestWithPlatformKey'
        }
    },
    {
        'name': 'test-vm_OsDisk_1_e6b7c388f6e0463a8a626a57fce96801',
        'id': '/subscriptions/123/resourceGroups/AKHTAR-RG/providers/Microsoft.Compute/disks/test-vm_OsDisk_1_e6b7c388f6e0463a8a626a57fce96801',
        'type': 'Microsoft.Compute/disks'
    },
    {
        'name': 'test-vm_OsDisk_1_e6b7c388f6e0463a8a626a57fce96801',
        'id': '/subscriptions/123/resourceGroups/AKHTAR-RG/providers/Microsoft.Compute/disks/test-vm_OsDisk_1_e6b7c388f6e0463a8a626a57fce96801',
        'type': 'Microsoft.Compute/disks',
        'encryption': {
            'type': 'EncryptionAtRestWithPlatformKey'
        }
    }
];

const createCache = (disks) => {
    let disk = {};
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

describe('vmDiskOSEncryption', function() {
    describe('run', function() {
        it('should give passing result if no disks', function(done) {
            const cache = createCache([]);
            vmDiskOSEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing disks found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for disks', function(done) {
            const cache = createCache();
            vmDiskOSEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Disks');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no OS disks found', function(done) {
            const cache = createCache([disks[0]]);
            vmDiskOSEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No OS disks found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if OS disk encryption is enabled', function(done) {
            const cache = createCache([disks[2]]);
            vmDiskOSEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('OS disk encryption is enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if OS disk encryption is disabled', function(done) {
            const cache = createCache([disks[1]]);
            vmDiskOSEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('OS disk encryption is disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});