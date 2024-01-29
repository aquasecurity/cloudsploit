var expect = require('chai').expect;
var vmDiskAutoKeyRotationCMK = require('./vmDiskCMKRotation');

const disks = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Compute/disks/test-disk",
        "name": "test-disk",
        "location": "eastus",
        "encryption": {
            "type": "EncryptionAtRestWithPlatformKey"
        }
    },
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Compute/disks/test-disk-cmk",
        "name": "test-disk-cmk",
        "location": "eastus",
        "encryption": {
            "diskEncryptionSetId": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Compute/diskEncryptionSets/test-disk-es"
        }
    }
];

const diskEncryptionSet = {
    "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Compute/diskEncryptionSets/test-disk-es",
    "name": "test-disk-es",
    "location": "eastus",
    "rotationToLatestKeyVersionEnabled": true
};

const createCache = (disks, diskEncryptionSet) => {
    const diskId = (disks && disks.length) ? disks[0].id : null;
    return {
        disks: {
            list: {
                'eastus': {
                    data: disks
                }
            }
        },
        diskEncryptionSet: {
            get: {
                'eastus': { 
                    [diskId]: { 
                        data: diskEncryptionSet
                    }
                }
            }
        }
    };
};

describe('vmDiskAutoKeyRotationCMK', function() {
    describe('run', function() {
        it('should give passing result if no disk volumes found', function(done) {
            const cache = createCache([], null);
            vmDiskAutoKeyRotationCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing disk volumes found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for disk volumes', function(done) {
            const cache = createCache(null, null);
            vmDiskAutoKeyRotationCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machine disk volumes:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if disk is using platform managed key', function(done) {
            const cache = createCache([disks[0]], null);
            vmDiskAutoKeyRotationCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Disk is encrypted using a platform managed key');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if disk auto key rotation for customer managed key is enabled', function(done) {
            const cache = createCache([disks[1]], diskEncryptionSet);
            vmDiskAutoKeyRotationCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Disk has automatic key rotation enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if disk auto key rotation for customer managed key is disabled', function(done) {
            const cache = createCache([disks[1]], { rotationToLatestKeyVersionEnabled: false });
            vmDiskAutoKeyRotationCMK.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Disk does not have automatic key rotation enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
