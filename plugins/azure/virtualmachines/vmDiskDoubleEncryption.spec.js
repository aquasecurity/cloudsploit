var expect = require('chai').expect;
var vmDiskDoubleEncryption = require('./vmDiskDoubleEncryption');

const disks = [
    {
        'name': 'test-vm_disk1_151553523',
        'id': '/subscriptions/123/resourceGroups/AKHTAR-RG/providers/Microsoft.Compute/disks/test-vm_disk1_151553523',
        'type': 'Microsoft.Compute/disks',
        'encryption': {
            'type': 'EncryptionAtRestWithPlatformAndCustomerKeys'
        }
    },
    
    {
        'name': 'test-vm_OsDisk_1_53523231',
        'id': '/subscriptions/123/resourceGroups/AKHTAR-RG/providers/Microsoft.Compute/disks/test-vm_OsDisk_1_53523231',
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

describe('vmDiskDoubleEncryption', function() {
    describe('run', function() {
        it('should give passing result if no disks', function(done) {
            const cache = createCache([]);
            vmDiskDoubleEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing disks found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for disks', function(done) {
            const cache = createCache();
            vmDiskDoubleEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for disks');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if double encryption is enabled', function(done) {
            const cache = createCache([disks[0]]);
            vmDiskDoubleEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VM disk is double encrypted using both platform and customer managed keys');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if double encryption is not enabled', function(done) {
            const cache = createCache([disks[1]]);
            vmDiskDoubleEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('VM disk is encrypted using only');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});